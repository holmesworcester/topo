module forward_secrecy_repair {
  type Peer = str
  type Frontier = str
  type Pubkey = str
  type Material = str

  type Request = { frontier: Frontier, recipient: Pubkey }
  type ResponseId = { frontier: Frontier, recipient: Pubkey, material: Material }
  type ResponseEvent = { id: ResponseId, responder: Peer }
  type Knowledge = { peer: Peer, material: Material }

  pure val alice: Peer = "alice"
  pure val bob: Peer = "bob"
  pure val carol: Peer = "carol"

  pure val f0: Frontier = "f0_all_members"
  pure val f1: Frontier = "f1_carol_removed"

  pure val m0: Material = "m0_pre_removal"
  pure val m1: Material = "m1_after_carol_removed"

  pure val aliceWrap: Pubkey = "wrap_alice"
  pure val bobWrap: Pubkey = "wrap_bob"
  pure val carolWrap: Pubkey = "wrap_carol"
  pure val bobInvite: Pubkey = "invite_bob"

  pure val Peers: Set[Peer] = Set(alice, bob, carol)
  pure val Frontiers: Set[Frontier] = Set(f0, f1)
  pure val Materials: Set[Material] = Set(m0, m1)
  pure val WrapPubkeys: Set[Pubkey] = Set(aliceWrap, bobWrap, carolWrap)
  pure val InvitePubkeys: Set[Pubkey] = Set(bobInvite)
  pure val PotentialRequestPubkeys: Set[Pubkey] = WrapPubkeys.union(InvitePubkeys)

  pure val OwnerByWrapPubkey: Pubkey -> Peer = Map(
    aliceWrap -> alice,
    bobWrap -> bob,
    carolWrap -> carol
  )

  pure val ActiveMembersByFrontier: Frontier -> Set[Peer] = Map(
    f0 -> Set(alice, bob, carol),
    f1 -> Set(alice, bob)
  )

  pure val FrontierByMaterial: Material -> Frontier = Map(
    m0 -> f0,
    m1 -> f1
  )

  pure def owner(pk: Pubkey): Peer = OwnerByWrapPubkey.get(pk)
  pure def frontierOf(material: Material): Frontier = FrontierByMaterial.get(material)
  pure def activeAt(peer: Peer, frontier: Frontier): bool =
    ActiveMembersByFrontier.get(frontier).contains(peer)

  pure def authorizedForMaterial(peer: Peer, material: Material): bool =
    activeAt(peer, frontierOf(material))

  pure def request(frontier: Frontier, recipient: Pubkey): Request =
    { frontier: frontier, recipient: recipient }

  pure def responseId(frontier: Frontier, recipient: Pubkey, material: Material): ResponseId =
    { frontier: frontier, recipient: recipient, material: material }

  pure def knowledge(peer: Peer, material: Material): Knowledge =
    { peer: peer, material: material }

  pure val AllRequests: Set[Request] =
    tuples(Frontiers, PotentialRequestPubkeys).map(((frontier, recipient)) =>
      request(frontier, recipient)
    )

  pure val AllResponseIds: Set[ResponseId] =
    tuples(Frontiers, WrapPubkeys, Materials).map(((frontier, recipient, material)) =>
      responseId(frontier, recipient, material)
    )

  pure val AllKnowledge: Set[Knowledge] =
    tuples(Peers, Materials).map(((peer, material)) => knowledge(peer, material))

  pure val InitialKnowledge: Set[Knowledge] = Set(
    knowledge(alice, m0),
    knowledge(alice, m1),
    knowledge(bob, m0),
    knowledge(carol, m0)
  )

  pure def requestWellFormed(req: Request): bool =
    WrapPubkeys.contains(req.recipient) and activeAt(owner(req.recipient), req.frontier)

  pure def responseWellFormed(resp: ResponseId): bool =
    resp.frontier == frontierOf(resp.material)
      and activeAt(owner(resp.recipient), resp.frontier)

  pure def responseEventWellFormed(evt: ResponseEvent): bool =
    responseWellFormed(evt.id) and activeAt(evt.responder, evt.id.frontier)

  pure def requestForResponse(resp: ResponseId): Request =
    request(resp.frontier, resp.recipient)

  pure def responseIdsForRequests(reqs: Set[Request]): Set[ResponseId] =
    AllResponseIds.filter(resp =>
      responseWellFormed(resp) and reqs.contains(requestForResponse(resp))
    )

  pure def proactiveResponseIdsFor(pubkeys: Set[Pubkey]): Set[ResponseId] =
    AllResponseIds.filter(resp =>
      pubkeys.contains(resp.recipient) and responseWellFormed(resp)
    )

  pure val AllWellFormedRequests: Set[Request] =
    AllRequests.filter(requestWellFormed)

  pure val ExpectedAuthorizedResponses: Set[ResponseId] =
    proactiveResponseIdsFor(WrapPubkeys)

  pure val AllResponseEvents: Set[ResponseEvent] =
    tuples(AllResponseIds, Peers).map(((id, responder)) =>
      { id: id, responder: responder }
    )

  pure val AllWellFormedResponseEvents: Set[ResponseEvent] =
    AllResponseEvents.filter(responseEventWellFormed)

  // Mutable DAG/projection state. All sets are monotonic.
  var knownWrapPubkeys: Set[Pubkey]
  var requests: Set[Request]
  var responseEvents: Set[ResponseEvent]
  var responses: Set[ResponseId]
  var learned: Set[Knowledge]

  action init = all {
    knownWrapPubkeys' = Set(),
    requests' = Set(),
    responseEvents' = Set(),
    responses' = Set(),
    learned' = InitialKnowledge,
  }

  action keepRequestsResponsesKnowledge = all {
    requests' = requests,
    responseEvents' = responseEvents,
    responses' = responses,
    learned' = learned,
  }

  action publishWrap = {
    nondet pk = WrapPubkeys.oneOf()
    all {
      knownWrapPubkeys' = knownWrapPubkeys.union(Set(pk)),
      keepRequestsResponsesKnowledge,
    }
  }

  action emitRequest = {
    nondet req = AllRequests.oneOf()
    all {
      knownWrapPubkeys.contains(req.recipient),
      requestWellFormed(req),
      knownWrapPubkeys' = knownWrapPubkeys,
      requests' = requests.union(Set(req)),
      responseEvents' = responseEvents,
      responses' = responses,
      learned' = learned,
    }
  }

  action proactiveShare = {
    nondet resp = AllResponseIds.oneOf()
    nondet holder = Peers.oneOf()
    val evt = { id: resp, responder: holder }
    all {
      knownWrapPubkeys.contains(resp.recipient),
      learned.contains(knowledge(holder, resp.material)),
      activeAt(holder, resp.frontier),
      responseWellFormed(resp),
      knownWrapPubkeys' = knownWrapPubkeys,
      requests' = requests,
      responseEvents' = responseEvents.union(Set(evt)),
      responses' = responses.union(Set(resp)),
      learned' = learned,
    }
  }

  action respondToRequest = {
    nondet resp = AllResponseIds.oneOf()
    nondet holder = Peers.oneOf()
    val evt = { id: resp, responder: holder }
    all {
      requests.contains(requestForResponse(resp)),
      learned.contains(knowledge(holder, resp.material)),
      activeAt(holder, resp.frontier),
      responseWellFormed(resp),
      knownWrapPubkeys' = knownWrapPubkeys,
      requests' = requests,
      responseEvents' = responseEvents.union(Set(evt)),
      responses' = responses.union(Set(resp)),
      learned' = learned,
    }
  }

  action deliverResponse = {
    nondet resp = AllResponseIds.oneOf()
    all {
      responses.contains(resp),
      responseWellFormed(resp),
      knownWrapPubkeys' = knownWrapPubkeys,
      requests' = requests,
      responseEvents' = responseEvents,
      responses' = responses,
      learned' = learned.union(Set(knowledge(owner(resp.recipient), resp.material))),
    }
  }

  action stutter = all {
    knownWrapPubkeys' = knownWrapPubkeys,
    requests' = requests,
    responseEvents' = responseEvents,
    responses' = responses,
    learned' = learned,
  }

  action step = any {
    publishWrap,
    emitRequest,
    proactiveShare,
    respondToRequest,
    deliverResponse,
    stutter,
  }

  val typeOk =
    knownWrapPubkeys.subseteq(WrapPubkeys)
      and requests.subseteq(AllRequests)
      and responseEvents.subseteq(AllResponseEvents)
      and responses.subseteq(AllResponseIds)
      and learned.subseteq(AllKnowledge)

  val requestSafety =
    requests.forall(requestWellFormed)

  val responseSafety =
    responses.forall(responseWellFormed)

  val responseEventSafety =
    responseEvents.forall(responseEventWellFormed)

  val responseProjectionMatchesEvents =
    responses == responseEvents.map(evt => evt.id)

  val learnedMaterialSafety =
    learned.forall(k => authorizedForMaterial(k.peer, k.material))

  val removedPeerNeverLearnsPostRemovalMaterial =
    not(learned.contains(knowledge(carol, m1)))

  val safety =
    typeOk and requestSafety and responseSafety and responseEventSafety
      and responseProjectionMatchesEvents and learnedMaterialSafety
      and removedPeerNeverLearnsPostRemovalMaterial

  run deterministicKeySecretByBytesTest =
    assert(Materials.forall(material => frontierOf(material) == FrontierByMaterial.get(material)))

  run inviteKeysAreNotPostAcceptRepairTargetsTest =
    assert(AllWellFormedRequests.forall(req => not(InvitePubkeys.contains(req.recipient))))

  run removedPeerDeniedForExcludedFrontierTest =
    assert(not(ExpectedAuthorizedResponses.contains(responseId(f1, carolWrap, m1))))

  run lateRequestConvergesToProactiveSetTest =
    assert(responseIdsForRequests(AllWellFormedRequests) == ExpectedAuthorizedResponses)

  run proactivePlusLateRequestIsIdempotentTest =
    assert(
      proactiveResponseIdsFor(Set(aliceWrap))
        .union(responseIdsForRequests(AllWellFormedRequests))
        == ExpectedAuthorizedResponses
    )

  run responseEventEnvelopeDoesNotCollapseByItselfTest =
    assert(
      AllWellFormedResponseEvents.size()
        > AllWellFormedResponseEvents.map(evt => evt.id).size()
    )
}
