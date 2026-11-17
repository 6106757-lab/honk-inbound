Internal

- The quoted-name routing test drops the unreachable `RoutingOutbound` arm: the enum has only the `Simple` variant, so the test asserts on `as_str()` instead.
