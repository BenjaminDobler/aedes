import write from '../write.js'
import { noop } from '../utils.js'
import { ReasonCodes } from '../constants.js'

// [#833] MQTT 5.0 Enhanced Authentication (§4.12).
//
// The exchange is an N-round-trip challenge/response that spans CONNECT ->
// CONNACK. `connect.js` starts it (`startEnhancedAuth`) from the `authenticate`
// step of the connect pipeline, stashing completion closures on the client
// (`onSuccess` / `onFailure`) so this module never has to reach back into the
// connect pipeline or `doConnack`. Continuation AUTH packets are routed here by
// `handlers/index.js`.

// Build a server->client AUTH packet. The Authentication Method is constant for
// the whole exchange (§4.12); Authentication Data and any extra properties are
// per step.
function serverAuthPacket (method, reasonCode, data, properties) {
  const props = { ...properties, authenticationMethod: method }
  if (data !== undefined) {
    props.authenticationData = data
  }
  return { cmd: 'auth', reasonCode, properties: props }
}

// Upper bound on exchange rounds. Common mechanisms (SCRAM) need two; this leaves
// generous headroom for multi-step ones while capping how many hook invocations a
// single connection can force within the deadline below. [DoS]
const MAX_AUTH_ROUNDS = 8

// One absolute deadline for the whole exchange (armed once in startEnhancedAuth,
// NOT re-armed per round): a client answering each challenge just under the
// timeout must not hold a half-open, unregistered connection open indefinitely.
// These sockets aren't in broker.clients yet, so they escape client-count limits.
// `handleConnect` cleared the original connect timer, so nothing else covers this.
function armAuthTimer (client) {
  clearTimeout(client._enhancedAuthTimer)
  client._enhancedAuthTimer = setTimeout(function authTimeout () {
    if (!client._enhancedAuth) return
    client._enhancedAuth = null
    // Close (like a connect timeout) rather than answer an unresponsive client.
    client.emit('error', new Error('enhanced authentication did not complete in time'))
  }, client.broker.connectTimeout)
  if (typeof client._enhancedAuthTimer.unref === 'function') {
    client._enhancedAuthTimer.unref()
  }
}

// Terminate the exchange and resume the stashed connect continuation.
function finishAuth (client, err) {
  const state = client._enhancedAuth
  client._enhancedAuth = null
  clearTimeout(client._enhancedAuthTimer)
  client._enhancedAuthTimer = null
  if (err) {
    state.onFailure(err)
  } else {
    state.onSuccess()
  }
}

// Run one step: hand the current Authentication Data to the broker's hook and
// act on the result — reject, accept, or send another challenge.
function runEnhancedAuthStep (client, data) {
  // Don't invoke the hook on a connection that already went away.
  if (client.closed || client.broker.closed) return
  const state = client._enhancedAuth
  if (++state.rounds > MAX_AUTH_ROUNDS) {
    finishAuth(client, Object.assign(new Error('enhanced authentication exceeded the maximum number of rounds'), { reasonCode: ReasonCodes.NOT_AUTHORIZED }))
    return
  }
  // Pause the read loop while the hook is pending so no further packet (a stray
  // second AUTH, a premature PUBLISH) is processed mid-step.
  client.pause()
  // Latch the callback: a misbehaving hook that fires twice (continue-then-throw,
  // continue-twice, done-then-error) must act on its first outcome only.
  let settled = false
  try {
    client.broker.authenticateEnhanced(client, state.method, data, function onResult (err, result) {
      if (settled) return
      settled = true
      // The connection may have gone away, or a newer exchange replaced this one,
      // while the hook was pending.
      if (client.closed || client.broker.closed || client._enhancedAuth !== state) {
        return
      }
      if (err) {
        finishAuth(client, err)
        return
      }
      if (result && result.done) {
        // Success. Stash any final Authentication Data for doConnack to MERGE
        // into the CONNACK properties (see connect.js — must not replace them).
        if (result.data !== undefined) {
          client._authenticationData = result.data
        }
        finishAuth(client, null)
        return
      }
      // Continue: challenge the client, then read its reply — from the wire
      // (resume) or, if pipelined ahead, from the pre-connected queue.
      write(client, serverAuthPacket(state.method, ReasonCodes.CONTINUE_AUTHENTICATION, result && result.data, result && result.properties), noop)
      client.resume()
      client._dispatchQueuedAuth()
    })
  } catch (err) {
    // A synchronously-throwing hook is contained as an auth failure rather than
    // taking down the connect pipeline (unless it already settled by continuing).
    if (!settled) {
      settled = true
      if (client._enhancedAuth === state) {
        finishAuth(client, err)
      }
    }
  }
}

// Called from the connect pipeline's `authenticate` action for a CONNECT that
// carried an Authentication Method and a configured `authenticateEnhanced` hook.
// `state` = { method, onSuccess, onFailure }.
function startEnhancedAuth (client, packet, state) {
  state.rounds = 0
  client._enhancedAuth = state
  // Arm the whole-exchange deadline once, up front.
  armAuthTimer(client)
  runEnhancedAuthStep(client, packet.properties?.authenticationData)
}

// Route an inbound AUTH packet: a continuation of the in-progress exchange.
function handleAuth (client, packet, done) {
  const state = client._enhancedAuth
  const method = packet.properties?.authenticationMethod
  if (!state) {
    // No exchange in flight. A connected client sending AUTH is attempting
    // re-authentication (0x19), which is not yet supported (#833 fast-follow) —
    // reject it (0x83 Implementation specific error) rather than dropping the
    // connection silently.
    client.broker.emit('clientError', client, new Error('unexpected AUTH packet'))
    if (client.connected) {
      client.disconnect({ reasonCode: ReasonCodes.IMPLEMENTATION_SPECIFIC_ERROR }, () => done())
    } else {
      client.close()
      done()
    }
    return
  }
  // §4.12: a continuation AUTH must carry reason code 0x18 (Continue
  // authentication) and the same Authentication Method as the CONNECT.
  if (method !== state.method || packet.reasonCode !== ReasonCodes.CONTINUE_AUTHENTICATION) {
    finishAuth(client, Object.assign(new Error('invalid continuation AUTH (method or reason code)'), { reasonCode: ReasonCodes.PROTOCOL_ERROR }))
    done()
    return
  }
  runEnhancedAuthStep(client, packet.properties?.authenticationData)
  done()
}

export { startEnhancedAuth }
export default handleAuth
