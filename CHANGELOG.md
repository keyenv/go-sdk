# Changelog

## [1.2.1](https://github.com/keyenv/go-sdk/compare/v1.2.0...v1.2.1) (2026-02-23)


### Bug Fixes

* remove trailing '/api/v1' from baseURL in New function ([7edbc1f](https://github.com/keyenv/go-sdk/commit/7edbc1f051f7ea4e5a139071d948ae443c1ab486))
* security and correctness fixes with test coverage ([adc532c](https://github.com/keyenv/go-sdk/commit/adc532c169fc2f01751fc61413993b6e7df99836))
* standardize API response envelope to use data wrapper ([3f43030](https://github.com/keyenv/go-sdk/commit/3f4303066cd2940a9ba6915734f2e9f25fa41b30))
* unwrap data envelope for single-resource API responses ([c1e240e](https://github.com/keyenv/go-sdk/commit/c1e240e29de4b1168957a294712c803965f40491))

## [1.2.0](https://github.com/keyenv/go-sdk/compare/v1.1.0...v1.2.0) (2026-01-26)


### Features

* add ValidateToken, CreateProject, DeleteProject, CreateEnvironment, DeleteEnvironment ([f3a87c0](https://github.com/keyenv/go-sdk/commit/f3a87c06aafd67970a4a6544b6821b2992ef453f))


### Bug Fixes

* correct module path to match repo name ([fb2ec63](https://github.com/keyenv/go-sdk/commit/fb2ec637ccc9d77bfeba66717fb5f44fb449985a))
* correct permission endpoint paths ([#1](https://github.com/keyenv/go-sdk/issues/1)) ([b72d0bc](https://github.com/keyenv/go-sdk/commit/b72d0bca11f4285f4405a44245723c8eddffebcc))
* update user authentication handling and response structure ([36c647f](https://github.com/keyenv/go-sdk/commit/36c647f968647ee19c280cda5b417006a2217981))
