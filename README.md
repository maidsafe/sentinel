[![Stories in Ready](https://badge.waffle.io/maidsafe/sentinel.png?label=ready&title=Ready)](https://waffle.io/maidsafe/sentinel)
# Sentinel

**Primary Maintainer:**     Peter Jankuliak (peter.jankuliak@maidsafe.net)

**Secondary Maintainer:**   Benjamin Bollen (benjamin.bollen@maidsafe.net)

|Crate|Linux|Windows|OSX|Coverage|
|:------:|:-------:|:-------:|:-------:|:-------:|
|[![](http://meritbadge.herokuapp.com/sentinel)](https://crates.io/crates/sentinel)|[![Build Status](https://travis-ci.org/maidsafe/sentinel.svg?branch=master)](https://travis-ci.org/maidsafe/sentinel)| [![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=sentinel_win64_status_badge)](http://ci.maidsafe.net:8080/job/sentinel_win64_status_badge/)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=sentinel_osx_status_badge)](http://ci.maidsafe.net:8080/job/sentinel_osx_status_badge/)|[![Coverage Status](https://coveralls.io/repos/maidsafe/sentinel/badge.svg)](https://coveralls.io/r/maidsafe/sentinel)|

| [API Documentation - Master branch](http://maidsafe.github.io/sentinel/sentinel/) | [SAFENetwork System Documention](http://systemdocs.maidsafe.net/) | [MaidSafe website](http://www.maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |

#Overview
Confirm group based consensus on messages in a p2p network

#Todo Items

## [0.0.2] Implement the three sentinels
- [x] [MAID-1061](https://maidsafe.atlassian.net/browse/MAID-1061) Move Frequency back here into this crate
- [x] [MAID-1074](https://maidsafe.atlassian.net/browse/MAID-1074) Remove dependency on the custom fork of the sodiumdioxide library
- [x] [MAID-1022](https://maidsafe.atlassian.net/browse/MAID-1022) Implement KeyStore
- [x] [MAID-1023](https://maidsafe.atlassian.net/browse/MAID-1023) Test KeyStore
- [x] [MAID-1024](https://maidsafe.atlassian.net/browse/MAID-1024) Implement PureSentinel
- [x] [MAID-1025](https://maidsafe.atlassian.net/browse/MAID-1025) Test PureSentinel
- [x] [MAID-1026](https://maidsafe.atlassian.net/browse/MAID-1026) Implement AccountSentinel
- [x] [MAID-1027](https://maidsafe.atlassian.net/browse/MAID-1027) Test AccountSentinel
- [x] [MAID-1030](https://maidsafe.atlassian.net/browse/MAID-1030) Implement KeySentinel
- [x] [MAID-1031](https://maidsafe.atlassian.net/browse/MAID-1031) Test KeySentinel
