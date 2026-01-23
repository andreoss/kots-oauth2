package kots.oauth2.host

import munit.FunSuite

final case class Threat(
    threat: String,
    mitigation: String,
    suite: munit.Suite,
    test: String
)

class ThreatModelSpec extends FunSuite {

  private val negative = new NegativeSpec

  private val interpreter = new InterpreterSpec

  private val model: List[Threat] = List(
    Threat(
      "authorization code replay",
      "codes are single use and a replay revokes the family it issued",
      negative,
      "a replayed code revokes the tokens it already issued"
    ),
    Threat(
      "open redirector",
      "redirect targets match the registration exactly and never bounce elsewhere",
      negative,
      "an unregistered redirect uri is refused without a redirect"
    ),
    Threat(
      "pkce downgrade",
      "only the S256 challenge method is accepted",
      negative,
      "a downgrade to the plain challenge method is refused without a code"
    ),
    Threat(
      "stolen code exchanged without possession",
      "the token endpoint demands the proven verifier",
      negative,
      "a token request without the proven verifier is refused"
    ),
    Threat(
      "algorithm confusion",
      "signature algorithms come from an asymmetric allow-list",
      negative,
      "a proof by an unsigned or symmetric algorithm is refused"
    ),
    Threat(
      "proof replay",
      "proof identifiers are remembered for the freshness window",
      negative,
      "a replayed proof is refused"
    ),
    Threat(
      "expired credential use",
      "expiry is enforced on every lookup and expired records purge",
      negative,
      "an expired access token is introspected as inactive"
    ),
    Threat(
      "audience confusion",
      "tokens carry their audience and the resource guard refuses a foreign one",
      negative,
      "a token minted for one resource is refused by another resource server"
    ),
    Threat(
      "binding bypass",
      "confirmation claims are granted only to the client that proved its key",
      negative,
      "a binding is granted only to the client that proved its certificate"
    ),
    Threat(
      "token endpoint flooding",
      "request rates are limited per client with a retry hint",
      interpreter,
      "a flooded token endpoint answers too many requests with a retry hint"
    ),
    Threat(
      "credential leakage through caches",
      "credential responses are served with cache control no-store",
      interpreter,
      "a refused token is served with cache control no-store"
    ),
    Threat(
      "issuer mix-up",
      "every authorization response names its issuer and carries the state",
      interpreter,
      "the authorization endpoint answers the full code flow end to end"
    ),
    Threat(
      "client impersonation over the wire",
      "a certificate authenticates only its registered client",
      interpreter,
      "a certificate of another key is refused as invalid client"
    ),
    Threat(
      "guessed or reused secrets",
      "authentication failures reveal nothing and are refused uniformly",
      interpreter,
      "a form post with a wrong secret is answered with unauthorized"
    )
  )

  test("every threat names its mitigation and the test that proves it") {
    model.foreach { entry =>
      val names = entry.suite.munitTests().map(_.name).toSet
      assert(
        names.contains(entry.test),
        s"${entry.threat}: no test named '${entry.test}' in ${entry.suite.getClass.getName}"
      )
      assert(entry.mitigation.nonEmpty, entry.threat)
    }
  }

  test("the model is free of duplicates and spans the negative tier") {
    assertEquals(model.map(_.threat).distinct.size, model.size)
    assertEquals(model.map(_.test).distinct.size, model.size)
    assert(model.size >= 14)
    assert(model.exists(_.suite eq negative))
    assert(model.exists(_.suite eq interpreter))
  }
}
