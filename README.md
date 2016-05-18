# drachtio-mw-blackhole-scanners
[drachtio](https://github.com/davehorton/drachtio) middleware to detect and block SIP scanners based on pattern match headers.  Incoming messages with headers that match any of the provided patterns are added to an iptables chain of your choosing which simply drops further packets from that address.

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

app.use( blackhole( opts ) );

```
