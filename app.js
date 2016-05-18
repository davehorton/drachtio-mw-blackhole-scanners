'use strict' ;

var iptables = require('iptables') ;
var _ = require('lodash') ;
var spawn = require('child_process').spawn;
var assert = require('assert') ;
var debug = require('drachtio-mw-blackhole-scanners') ;

module.exports = function(opts) {
  assert.ok( typeof opts.chain === 'string', '\'opts.chain\' is required') ;
  assert.ok( typeof opts.match === 'object', '\'opts.match\' is required') ;

  var chain  = opts.chain ;
  var matchObject = opts.match ;
  var rejectWith = opts.rejectWith || 403 ;
  var process = true ;

  // verify the chain exists
  var cmd = spawn('sudo', ['iptables','-S', chain]);
  cmd.stderr.on('data', function(buf) {
      console.error('error listing chain %s: ', chain, String(buf)) ;
      process = false ;
  }) ;

  return function (req, res, next) {
    if( !process ) { return next(); }

    var blackholed = false ;
    _.each( matchObject, function(value, key) {
      var matches = 'string' === typeof value ? [value] : value ;
      matches.forEach( function( pattern ) {
        if( blackholed || !req.has(key) ) { return; }
        if( req.get(key).match( pattern ) ) {

          debug('adding src %s/%s to the blacklist because of %s:%s', req.source_address, req.protocol, key, value) ;
          iptables.drop({
            chain: chain,
            src: req.source_address,
            dport: 5060,
            protocol: req.protocol,
            sudo: true
          }) ;
          blackholed = true ;
        }
      }) ;
    }); 

    if( blackholed ) { 
      return res.send(rejectWith) ;
    }
    
    next() ;
  } ;
} ;
