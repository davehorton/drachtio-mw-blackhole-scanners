# drachtio-mw-blackhole-scanners
Detect and block scanners based on pattern match headers (e.g. sipvicious User-Agent header)

```js
var drachtio            = require('drachtio') ;
var app                 = drachtio() ;
var blackhole           = require('drachtio-mw-blackhole-scanners')

var opts = {
  chain: 'LOGDROP',
  match: {
    'User-Agent': ['sip-cli','friendly-scanner', 'Asterisk PBX'],
    'To': 'sipvicious'
  }
  rejectWith: 503
} ;

app.use( blackhole( opts ) ;

```
