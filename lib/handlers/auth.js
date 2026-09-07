import write from '../write.js'
import { ReasonCodes } from '../constants.js'

// [#833] MQTT 5.0 Enhanced Authentication (§4.12).
//
// The exchange is an N-round-trip challenge/response that spans CONNECT ->
// CONNACK. `connect.js` starts it (`startEnhancedAuth`) from the `authenticate`
// step of the connect pipeline, stashing completion closures on the client
// (`onSuccess` / `onFailure`) so this module never has to reach back into the
// connect pipeline or `doConnack`. Continuation AUTH packets are routed here by
// `handlers/index.js`.

// Shape-check the auth properties an inbound packet (CONNECT or a continuation
// AUTH) carries, at the trust boundary, before they reach `authenticateEnhanced`.
// mqtt-packet decodes a duplicated v5 property into an ARRAY (itself a Protocol
// Error), so without this the hook could be handed `method: string[]` /
// `data: Buffer[]` — steering a SCRAM/OAuth length or prefix check onto the wrong
// branch. Well-shaped means: the Authentication Method (if present) is a single
// string, the Authentication Data (if present) a single Buffer. [#833]
function validAuthProperties (properties) {
  const method = properties?.authenticationMethod
  const data = properties?.authenticationData
  // §3.1.2.11.9 / §3.15.2.2.2: omission and duplication are Protocol Errors; a
  // duplicated v5 property decodes to an array, so a non-string method / non-Buffer
  // data is the array shape we must reject. An *empty-string* method is neither
  // omitted nor duplicated, so it is not a Protocol Error — leave it to the hook.
  if (method !== undefined && typeof method !== 'string') return false
  if (data !== undefined && !Buffer.isBuffer(data)) return false
  return true
}

// Per-call writeToStream options for a server AUTH: when the client advertised a
// Maximum Packet Size, hand it to mqtt-packet so it drops the optional Reason
// String / User Property to fit [MQTT-3.15.2-2/3]. undefined otherwise (the write
// path then uses its shared, allocation-free opts).
function authWriteOpts (client) {
  return client.maximumPacketSize > 0
    ? { properties: { maximumPacketSize: client.maximumPacketSize } }
    : undefined
}

// Build a server->client AUTH packet. The Authentication Method is constant for
// the whole exchange (§4.12) and Authentication Data is set per step; both are
// owned by aedes, not the hook. From a hook's `result.properties` only Reason
// String and User Property are forwarded — §3.15.2.2 permits nothing else on
// AUTH, and [MQTT-3.1.2-29] forbids Reason String / User Property when the client
// disabled Request Problem Information. Building `props` field-by-field (rather
// than spreading the hook object) also means a hook cannot override
// authenticationMethod / authenticationData.
function serverAuthPacket (client, method, reasonCode, data, properties) {
  const props = { authenticationMethod: method }
  if (data !== undefined) {
    props.authenticationData = data
  }
  if (properties && client._requestProblemInformation !== false) {
    if (properties.reasonString !== undefined) props.reasonString = properties.reasonString
    if (properties.userProperties !== undefined) props.userProperties = properties.userProperties
  }
  return { cmd: 'auth', reasonCode, properties: props }
}

// One absolute deadline for the whole exchange (armed once in startEnhancedAuth,
// NOT re-armed per round): a client answering each challenge just under the
// timeout must not hold a half-open, unregistered connection open indefinitely.
// These sockets aren't in broker.clients yet, so they escape client-count limits.
// `handleConnect` cleared the original connect timer, so nothing else covers this.
function armAuthTimer (client) {
  clearTimeout(client._enhancedAuthTimer)
  client._enhancedAuthTimer = setTimeout(function authTimeout () {
    // Reaching here means the exchange stalled: finishAuth clears this timer on
    // completion, and Client.close() clears it on disconnect, so it never fires
    // stale. Route through finishAuth (not a bare emit/close) so the timeout is
    // single-sourced with every other rejection — cleanup, reason code, and a
    // rejection CONNACK all handled the same way.
    const state = client._enhancedAuth
    if (!state) return
    // Distinguish the two very different faults this timeout covers — a stalled
    // client vs. a hook that never called back (the most likely rollout bug) — so
    // an operator isn't left chasing the network for a broker-side hook bug.
    const cause = state.pending
      ? `authenticateEnhanced still pending at round ${state.rounds}`
      : `awaiting client AUTH at round ${state.rounds}`
    finishAuth(client, Object.assign(new Error(`enhanced authentication did not complete in time (${cause})`), { reasonCode: ReasonCodes.NOT_AUTHORIZED }))
  }, client.broker.connectTimeout)
  client._enhancedAuthTimer.unref() // don't keep the process alive on this timer
}

// Terminate the exchange and resume the stashed connect continuation. `err` set =
// rejection; `err` null = acceptance (any final Authentication Data was stashed on
// the client beforehand).
function finishAuth (client, err) {
  const state = client._enhancedAuth
  client._enhancedAuth = null
  clearTimeout(client._enhancedAuthTimer)
  client._enhancedAuthTimer = null
  if (err) {
    state.onFailure(err)
    return
  }
  // Success — but a DISCONNECT may have arrived before we complete. Completing
  // would registerClient (evicting a live same-id session with 0x8E) and CONNACK
  // 0x00 for a client that already left. It can be in two places: still in the
  // socket buffer (arrived in a later segment while the read loop was paused) —
  // resume() reads it — OR already parsed into the pre-connected queue (pipelined
  // in the CONNECT's segment, before _enhancedAuth existed) — _dispatchQueuedAuth
  // drains it. Honor both, then abort the completion if the client disconnected.
  // _enhancedAuth is already nulled, so a stray buffered AUTH can't start a fresh
  // step.
  client.resume()
  client._dispatchQueuedAuth()
  if (client.closed || client.conn.destroyed) return
  // Re-pause before handing back to the connect pipeline. `authenticate` paused the
  // read loop at connect.js and every other connect path stays paused until
  // `emptyQueue` resumes it; without this, packets a client pipelines after its
  // final AUTH pile into `_parser._queue` for the whole rest of the pipeline
  // (fetchSubs → … → registerClient → doConnack) and past `queueLimit` (42) get the
  // connection killed instead of TCP-throttled.
  client.pause()
  state.onSuccess()
}

// Run one step: hand the current Authentication Data to the broker's hook and
// act on the result — reject, accept, or send another challenge.
function runEnhancedAuthStep (client, data) {
  // Don't invoke the hook or arm a timer on a connection that already went away
  // — e.g. a FIN/RST inside the setImmediate(init) window, before the exchange
  // starts, which would otherwise orphan a connectTimeout timer on a dead
  // connection (close() cleared nothing, as the timer wasn't armed yet).
  if (client.closed || client.conn.destroyed) return
  // Broker is shutting down. On round 0 the timer isn't armed yet, so a bare return
  // would leave _enhancedAuth set, the read loop paused, no timer, and neither
  // callback fired — the socket hangs with no CONNACK until the peer gives up, and
  // since it isn't in broker.clients yet, aedes.close() never reaches it. Fail the
  // exchange so onFailure sends a rejection CONNACK (0x88 Server unavailable) and
  // closes it. finishAuth tolerates the not-yet-armed timer.
  if (client.broker.closed) {
    finishAuth(client, Object.assign(new Error('broker is shutting down'), { reasonCode: ReasonCodes.SERVER_UNAVAILABLE }))
    return
  }
  const state = client._enhancedAuth
  // At most one hook step in flight per connection. A client that sends another
  // AUTH before the current step's hook resolves is violating the protocol, and
  // an overlapping call would corrupt a stateful mechanism's per-step state (e.g.
  // SCRAM's server nonce) — an authentication-bypass surface. The read loop is
  // paused across a step and `_dispatchQueuedAuth` is gated on `_paused`, so a
  // well-behaved one-AUTH-per-challenge client never hits this; only pipelined or
  // dribbled AUTHs do. Reject rather than start a concurrent hook call.
  if (state.pending) {
    finishAuth(client, Object.assign(new Error('AUTH received while an enhanced-auth step is in flight'), { reasonCode: ReasonCodes.PROTOCOL_ERROR }))
    return
  }
  // Arm the whole-exchange deadline once, on the first live step (not per round),
  // so it is only ever armed after the closed-check above has passed.
  if (state.rounds === 0) armAuthTimer(client)
  // Cap the rounds (broker.maxAuthRounds) an unauthenticated client can force.
  // Reject with 0x97 (Quota exceeded), distinct from a real credential failure.
  if (++state.rounds > client.broker.maxAuthRounds) {
    finishAuth(client, Object.assign(new Error(`enhanced authentication exceeded the maximum number of rounds (${client.broker.maxAuthRounds}) for method '${state.method}'`), { reasonCode: ReasonCodes.QUOTA_EXCEEDED }))
    return
  }
  // Pause the read loop while the hook is pending so no further packet (a stray
  // second AUTH, a premature PUBLISH) is processed mid-step.
  state.pending = true
  client.pause()
  // The `try` wraps ONLY the hook invocation. When a hook calls back synchronously
  // (the documented example does), its outcome is recorded and acted on AFTER the
  // hook returns — so a throw from the downstream work finishAuth drives (a will
  // publish, a user `clientDisconnect` listener, a nested round) propagates
  // normally instead of being caught here and misattributed to the auth hook.
  // `settled` latches: a hook that fires twice acts on its first outcome only.
  let settled = false
  let hookReturned = false
  let syncOutcome = null
  let hookError = null
  try {
    client.broker.authenticateEnhanced(client, state.method, data, function onResult (err, result) {
      if (settled) return
      settled = true
      state.pending = false
      if (hookReturned) {
        // Asynchronous callback: the hook already returned, so act now (already
        // outside the try).
        processOutcome(err, result)
      } else {
        // Synchronous callback: defer until the hook returns (see below).
        syncOutcome = { err, result }
      }
    })
  } catch (err) {
    hookError = err
  }
  hookReturned = true
  if (syncOutcome) processOutcome(syncOutcome.err, syncOutcome.result)
  if (hookError) {
    if (!settled) {
      // The hook threw before calling back — contain it as an auth failure rather
      // than taking down the connect pipeline.
      settled = true
      state.pending = false
      if (client._enhancedAuth === state) finishAuth(client, hookError)
    } else {
      // The hook called back (its outcome was processed above) and then threw: the
      // exchange can't be failed twice, but a broken hook shouldn't be silent.
      client.broker.emit(client.id ? 'clientError' : 'connectionError', client, hookError)
    }
  }

  // Act on the hook's outcome: reject, accept, or send another challenge.
  function processOutcome (err, result) {
    // The connection may have gone away (closed, or destroyed in the window before
    // close() runs), or a newer exchange replaced this one, while the hook was
    // pending. Nothing to do then.
    if (client.closed || client.conn.destroyed || client._enhancedAuth !== state) return
    // Broker is shutting down: fail the exchange (rejection CONNACK 0x88 + close)
    // rather than a bare return, which would leave the armed timer to resolve it only
    // after the full connectTimeout.
    if (client.broker.closed) {
      finishAuth(client, Object.assign(new Error('broker is shutting down'), { reasonCode: ReasonCodes.SERVER_UNAVAILABLE }))
      return
    }
    if (err) {
      finishAuth(client, err)
      return
    }
    // Fail closed: a hook that calls back with no result (`cb()` / `cb(null)` /
    // `cb(null, null)`) must reject, not fall through to "send another challenge" —
    // that would keep an unauthenticated connection alive in a challenge loop. Only
    // an explicit `{ done: false, ... }` continues. This matches the username/
    // password `authenticate` convention (`if (!err && successful)`), where a falsy
    // result is a rejection.
    if (result == null) {
      finishAuth(client, Object.assign(new Error('enhanced authentication hook returned no result'), { reasonCode: ReasonCodes.NOT_AUTHORIZED }))
      return
    }
    if (result.done) {
      // Stash any final Authentication Data for doConnack to MERGE into the CONNACK
      // properties (see connect.js — must not replace them). finishAuth then drains
      // any DISCONNECT buffered during the paused step and completes only if the
      // client is still connected.
      if (result.data !== undefined) {
        client._authenticationData = result.data
      }
      finishAuth(client, null)
      return
    }
    // Continue: challenge the client, then read its reply — from the wire (resume)
    // or, if pipelined ahead, from the pre-connected queue. Surface a challenge-
    // write failure rather than swallowing it — a dropped challenge would stall the
    // exchange until the deadline. Pass the client's Maximum Packet Size so
    // mqtt-packet drops the optional Reason String / User Property [MQTT-3.15.2-2/3]
    // rather than emitting an over-size AUTH the client must reject.
    write(client, serverAuthPacket(client, state.method, ReasonCodes.CONTINUE_AUTHENTICATION, result && result.data, result && result.properties), onWriteError, undefined, authWriteOpts(client))
    client.resume()
    client._dispatchQueuedAuth()
  }
  function onWriteError (err) {
    if (err) client.emit('error', err)
  }
}

// Called from the connect pipeline's `authenticate` action for a CONNECT that
// carried an Authentication Method and a configured `authenticateEnhanced` hook.
// `state` = { method, onSuccess, onFailure }.
function startEnhancedAuth (client, packet, state) {
  state.rounds = 0
  state.pending = false
  client._enhancedAuth = state
  runEnhancedAuthStep(client, packet.properties?.authenticationData)
}

// Route an inbound AUTH packet: a continuation of the in-progress exchange.
function handleAuth (client, packet, done) {
  const state = client._enhancedAuth
  const method = packet.properties?.authenticationMethod
  if (!state) {
    // No exchange in flight. Latch so N stray AUTH packets in one TCP segment
    // (all dispatched before the async close() lands) don't each emit an error and
    // a DISCONNECT — a small unauthenticated write amplification. The first one
    // tears the connection down; the rest are ignored.
    if (client._rejectingAuth) {
      done()
      return
    }
    client._rejectingAuth = true
    // Classify: per [MQTT-4.12.1-1] a genuine re-authentication is reason code 0x19
    // with the SAME Authentication Method the client negotiated — that single case
    // maps to 0x83 (Implementation specific error; aedes doesn't yet support
    // re-auth). Everything else is a Protocol Error → 0x82 (§4.13.1). Attach the
    // resolved reasonCode to the error (as rejectConnect / onFailure do) and use a
    // distinct message per branch, so a reject storm is diagnosable from the event
    // alone — "clients attempting unsupported re-auth" vs "protocol-broken clients".
    const isReauth = client._authenticationMethod !== undefined &&
      packet.reasonCode === ReasonCodes.REAUTHENTICATE &&
      method === client._authenticationMethod
    const reasonCode = isReauth
      ? ReasonCodes.IMPLEMENTATION_SPECIFIC_ERROR
      : ReasonCodes.PROTOCOL_ERROR
    const err = Object.assign(
      new Error(isReauth ? 'AUTH re-authentication is not supported' : 'unexpected AUTH packet'),
      { reasonCode })
    // Key on connackSent (set before `connected`, with the async emptyQueue drain
    // in between) so an AUTH in that window still gets a DISCONNECT, not a bare close.
    if (client.connackSent || client.connected) {
      client.broker.emit(client.id ? 'clientError' : 'connectionError', client, err)
      client.disconnect({ reasonCode }, () => done())
    } else {
      // Not yet connected: route through _onError (the 'error' listener) — the
      // established way to reject a packet from a pre-connack client (it selects
      // clientError/connectionError by id and tears down). Cf. rejectPacketTooLarge.
      client.emit('error', err)
      done()
    }
    return
  }
  // Shape-check the continuation AUTH at the trust boundary — the same check
  // init() runs on CONNECT — before the hook sees it. A duplicated Authentication
  // Data property decodes to a Buffer[], which the `method !== state.method` guard
  // below would not catch. [Blocker: the continuation is the one packet an
  // unauthenticated client fully controls and repeats every round.]
  if (!validAuthProperties(packet.properties)) {
    finishAuth(client, Object.assign(new Error('malformed authentication method or data'), { reasonCode: ReasonCodes.PROTOCOL_ERROR }))
    done()
    return
  }
  // §4.12: the Authentication Method must not change during the exchange.
  // §3.15.2.2.2 makes *omitting* it a Protocol Error (0x82); a *different* method is
  // 0x8C (Bad Authentication Method). Split them rather than conflating omission with
  // substitution.
  if (method === undefined) {
    finishAuth(client, Object.assign(new Error('continuation AUTH is missing the Authentication Method'), { reasonCode: ReasonCodes.PROTOCOL_ERROR }))
    done()
    return
  }
  if (method !== state.method) {
    finishAuth(client, Object.assign(new Error('authentication method changed mid-exchange'), { reasonCode: ReasonCodes.BAD_AUTHENTICATION_METHOD }))
    done()
    return
  }
  // A continuation AUTH must carry reason code 0x18 (Continue authentication).
  if (packet.reasonCode !== ReasonCodes.CONTINUE_AUTHENTICATION) {
    finishAuth(client, Object.assign(new Error('continuation AUTH must carry reason code 0x18'), { reasonCode: ReasonCodes.PROTOCOL_ERROR }))
    done()
    return
  }
  runEnhancedAuthStep(client, packet.properties?.authenticationData)
  done()
}

export { startEnhancedAuth, validAuthProperties }
export default handleAuth
