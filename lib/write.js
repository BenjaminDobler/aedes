import mqtt from 'mqtt-packet'

// Frozen, module-level writeToStream options per wire version, indexed by the
// resolved version. Avoids allocating a fresh `{ protocolVersion }` object on
// every write — this is the broker's universal (v3/v4 included) hot path.
const WRITE_OPTS = {
  3: Object.freeze({ protocolVersion: 3 }),
  4: Object.freeze({ protocolVersion: 4 }),
  5: Object.freeze({ protocolVersion: 5 })
}

// [#840] MQTT 5.0 outbound (broker-assigned) Topic Alias. When a client
// advertised a Topic Alias Maximum > 0 in its CONNECT, the broker MAY replace
// the topic of an outbound PUBLISH with a small integer alias to save bandwidth:
// the first PUBLISH on a topic carries the full topic name plus a Topic Alias
// (registering it for the connection); later PUBLISHes on that topic carry an
// empty topic and the alias. §3.3.2.3.4
//
// Returns the object to serialize — a shallow clone when aliased, so the
// caller's packet (which persistence may hold by reference for QoS > 0, and
// which must keep its real topic for resend after reconnect) is never mutated.
function withOutboundTopicAlias (client, packet, version) {
  const max = client._outboundTopicAliasMaximum
  // Only alias non-empty *string* topics: a Buffer topic (reachable via
  // client.publish(), which skips topic validation) would key the Map by object
  // identity, so an equal-but-distinct Buffer never matches — burning a fresh
  // alias slot per publish until the table is permanently full.
  if (!max || version !== 5 || packet.cmd !== 'publish' || typeof packet.topic !== 'string' || packet.topic === '') {
    return packet
  }
  // A caller-set Topic Alias (via the public client.publish()) is caller-owned:
  // forward it verbatim and don't broker-alias, so the broker's table can't
  // disagree with a hand-rolled one and misdeliver. (The empty-topic reuse form
  // already passes through the guard above.)
  if (packet.properties?.topicAlias !== undefined) {
    return packet
  }
  const aliases = client._outboundTopicAliases
  const known = aliases.get(packet.topic)
  if (known !== undefined) {
    // Registered topic: send an empty topic + the alias.
    return { ...packet, topic: '', properties: { ...packet.properties, topicAlias: known } }
  }
  if (aliases.size >= max) {
    // Alias table full — send the full topic name, no alias (never evict).
    return packet
  }
  // New topic: assign the next alias (1..max) and send the full topic + alias,
  // which registers the mapping on the client for subsequent PUBLISHes.
  //
  // The mapping is committed before writeToStream runs (see write() below). Safe
  // today: a serialize/flush failure calls _onError, which destroys the socket
  // and discards this per-connection map, so no later aliased send references an
  // alias the client never saw. It would stop being safe if a write path ever
  // *drops* a PUBLISH without tearing the connection down (e.g. the planned
  // outbound maximumPacketSize enforcement) — commit only after a successful
  // write if that lands. [#840]
  const alias = aliases.size + 1
  aliases.set(packet.topic, alias)
  return { ...packet, properties: { ...packet.properties, topicAlias: alias } }
}

function write (client, packet, done, protocolVersion) {
  let error = null
  if (client.connecting || client.connected) {
    try {
      // Serialize using the negotiated protocol version so that MQTT v5 reason
      // codes and properties are emitted. The version can be passed explicitly
      // (e.g. a rejection CONNACK before client.version is assigned); otherwise
      // use the version cached at CONNECT (client._wireVersion). Unknown/
      // unsupported versions default to v4 since mqtt-packet only serializes
      // v3/v4/v5.
      let version = client._wireVersion ?? 4
      if (protocolVersion !== undefined) {
        version = (protocolVersion === 3 || protocolVersion === 5) ? protocolVersion : 4
      }
      const toWrite = withOutboundTopicAlias(client, packet, version)
      const result = mqtt.writeToStream(toWrite, client.conn, WRITE_OPTS[version])
      if (!result && !client.errored) {
        // Socket buffer is full - wait for drain
        client.waitForDrain(done)
        return
      }
    } catch (e) {
      // Preserve the underlying cause so v5 DISCONNECT-with-properties encoding
      // failures (and the like) remain diagnosable.
      error = new Error('packet received not valid', { cause: e })
    }
  } else {
    error = new Error('connection closed')
  }

  setImmediate(done, error, client)
}

export default write
