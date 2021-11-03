/**
 * 镜像中只需要修改这个文件中的host,其它不用动
 */

Ext.define('ananas.ServerHosts',{
	alternateClassName : 'ServerHosts',
	singleton : true,
	constructor : function(){
		var me = this;
        me.callParent(arguments);
		var domain = document.domain;
		
		try{
			me.MASTER_HOST = location.protocol + '//'+ top.location.host;
		}catch(e){
			me.MASTER_HOST = location.protocol + '//'+ location.host;
		}
		try{
			me.PARENT_HOST = location.protocol + '//'+ parent.location.host;
		}catch(e){
			me.MASTER_HOST = location.protocol + '//'+ location.host;
		}
		me.P_HOST = location.protocol + '//p.ananas.chaoxing.com';
		me.s1_HOST = location.protocol + '//s1.ananas.chaoxing.com';
		me.s2_HOST = location.protocol + '//s2.ananas.chaoxing.com';
		me.CLOUD_HOST = 'http://cloud.ananas.' + domain;
		me.NEW_CLOUD_HOST = location.protocol  +  '//pan-yz.chaoxing.com';
		me.CS_HOST = location.protocol  + '//cs.ananas.' + domain;
		me.FANYA_HOST = 'http://course.fanya.' + domain;
		me.PAN_HOST = 'http://pan.ananas.' + domain;
		me.CXLIVE_HOST = 'http://cxlive.' + domain;
		me.ERYA_TSK_HOST = 'http://erya.tsk.' + domain;
		me.QUESTIONNAIRE_HOST = 'http://surveyapp.fy.' + domain;
		me.FX_HOST='http://www.' + domain;
		me.PHONE_ZT_HOST = "https://special.rhky.com";
		me.CHAOXING_CLASS_HOST = "https://k.chaoxing.com";
		me.LIVE_HOST = location.protocol + "//live.chaoxing.com";
		me.APPCD_HOST = location.protocol + "//appcd.chaoxing.com";
		me.ZHIBO_HOST = "https://zhibo.chaoxing.com";
	}
});
/*
 * JavaScript MD5
 * https://github.com/blueimp/JavaScript-MD5
 *
 * Copyright 2011, Sebastian Tschan
 * https://blueimp.net
 *
 * Licensed under the MIT license:
 * https://opensource.org/licenses/MIT
 *
 * Based on
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/* global define */

;(function ($) {
  'use strict'

  /*
  * Add integers, wrapping at 2^32. This uses 16-bit operations internally
  * to work around bugs in some JS interpreters.
  */
  function safeAdd (x, y) {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF)
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16)
    return (msw << 16) | (lsw & 0xFFFF)
  }

  /*
  * Bitwise rotate a 32-bit number to the left.
  */
  function bitRotateLeft (num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt))
  }

  /*
  * These functions implement the four basic operations the algorithm uses.
  */
  function md5cmn (q, a, b, x, s, t) {
    return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b)
  }
  function md5ff (a, b, c, d, x, s, t) {
    return md5cmn((b & c) | ((~b) & d), a, b, x, s, t)
  }
  function md5gg (a, b, c, d, x, s, t) {
    return md5cmn((b & d) | (c & (~d)), a, b, x, s, t)
  }
  function md5hh (a, b, c, d, x, s, t) {
    return md5cmn(b ^ c ^ d, a, b, x, s, t)
  }
  function md5ii (a, b, c, d, x, s, t) {
    return md5cmn(c ^ (b | (~d)), a, b, x, s, t)
  }

  /*
  * Calculate the MD5 of an array of little-endian words, and a bit length.
  */
  function binlMD5 (x, len) {
    /* append padding */
    x[len >> 5] |= 0x80 << (len % 32)
    x[(((len + 64) >>> 9) << 4) + 14] = len

    var i
    var olda
    var oldb
    var oldc
    var oldd
    var a = 1732584193
    var b = -271733879
    var c = -1732584194
    var d = 271733878

    for (i = 0; i < x.length; i += 16) {
      olda = a
      oldb = b
      oldc = c
      oldd = d

      a = md5ff(a, b, c, d, x[i], 7, -680876936)
      d = md5ff(d, a, b, c, x[i + 1], 12, -389564586)
      c = md5ff(c, d, a, b, x[i + 2], 17, 606105819)
      b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330)
      a = md5ff(a, b, c, d, x[i + 4], 7, -176418897)
      d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426)
      c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341)
      b = md5ff(b, c, d, a, x[i + 7], 22, -45705983)
      a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416)
      d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417)
      c = md5ff(c, d, a, b, x[i + 10], 17, -42063)
      b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162)
      a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682)
      d = md5ff(d, a, b, c, x[i + 13], 12, -40341101)
      c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290)
      b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329)

      a = md5gg(a, b, c, d, x[i + 1], 5, -165796510)
      d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632)
      c = md5gg(c, d, a, b, x[i + 11], 14, 643717713)
      b = md5gg(b, c, d, a, x[i], 20, -373897302)
      a = md5gg(a, b, c, d, x[i + 5], 5, -701558691)
      d = md5gg(d, a, b, c, x[i + 10], 9, 38016083)
      c = md5gg(c, d, a, b, x[i + 15], 14, -660478335)
      b = md5gg(b, c, d, a, x[i + 4], 20, -405537848)
      a = md5gg(a, b, c, d, x[i + 9], 5, 568446438)
      d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690)
      c = md5gg(c, d, a, b, x[i + 3], 14, -187363961)
      b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501)
      a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467)
      d = md5gg(d, a, b, c, x[i + 2], 9, -51403784)
      c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473)
      b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734)

      a = md5hh(a, b, c, d, x[i + 5], 4, -378558)
      d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463)
      c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562)
      b = md5hh(b, c, d, a, x[i + 14], 23, -35309556)
      a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060)
      d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353)
      c = md5hh(c, d, a, b, x[i + 7], 16, -155497632)
      b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640)
      a = md5hh(a, b, c, d, x[i + 13], 4, 681279174)
      d = md5hh(d, a, b, c, x[i], 11, -358537222)
      c = md5hh(c, d, a, b, x[i + 3], 16, -722521979)
      b = md5hh(b, c, d, a, x[i + 6], 23, 76029189)
      a = md5hh(a, b, c, d, x[i + 9], 4, -640364487)
      d = md5hh(d, a, b, c, x[i + 12], 11, -421815835)
      c = md5hh(c, d, a, b, x[i + 15], 16, 530742520)
      b = md5hh(b, c, d, a, x[i + 2], 23, -995338651)

      a = md5ii(a, b, c, d, x[i], 6, -198630844)
      d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415)
      c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905)
      b = md5ii(b, c, d, a, x[i + 5], 21, -57434055)
      a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571)
      d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606)
      c = md5ii(c, d, a, b, x[i + 10], 15, -1051523)
      b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799)
      a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359)
      d = md5ii(d, a, b, c, x[i + 15], 10, -30611744)
      c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380)
      b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649)
      a = md5ii(a, b, c, d, x[i + 4], 6, -145523070)
      d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379)
      c = md5ii(c, d, a, b, x[i + 2], 15, 718787259)
      b = md5ii(b, c, d, a, x[i + 9], 21, -343485551)

      a = safeAdd(a, olda)
      b = safeAdd(b, oldb)
      c = safeAdd(c, oldc)
      d = safeAdd(d, oldd)
    }
    return [a, b, c, d]
  }

  /*
  * Convert an array of little-endian words to a string
  */
  function binl2rstr (input) {
    var i
    var output = ''
    var length32 = input.length * 32
    for (i = 0; i < length32; i += 8) {
      output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF)
    }
    return output
  }

  /*
  * Convert a raw string to an array of little-endian words
  * Characters >255 have their high-byte silently ignored.
  */
  function rstr2binl (input) {
    var i
    var output = []
    output[(input.length >> 2) - 1] = undefined
    for (i = 0; i < output.length; i += 1) {
      output[i] = 0
    }
    var length8 = input.length * 8
    for (i = 0; i < length8; i += 8) {
      output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32)
    }
    return output
  }

  /*
  * Calculate the MD5 of a raw string
  */
  function rstrMD5 (s) {
    return binl2rstr(binlMD5(rstr2binl(s), s.length * 8))
  }

  /*
  * Calculate the HMAC-MD5, of a key and some data (raw strings)
  */
  function rstrHMACMD5 (key, data) {
    var i
    var bkey = rstr2binl(key)
    var ipad = []
    var opad = []
    var hash
    ipad[15] = opad[15] = undefined
    if (bkey.length > 16) {
      bkey = binlMD5(bkey, key.length * 8)
    }
    for (i = 0; i < 16; i += 1) {
      ipad[i] = bkey[i] ^ 0x36363636
      opad[i] = bkey[i] ^ 0x5C5C5C5C
    }
    hash = binlMD5(ipad.concat(rstr2binl(data)), 512 + data.length * 8)
    return binl2rstr(binlMD5(opad.concat(hash), 512 + 128))
  }

  /*
  * Convert a raw string to a hex string
  */
  function rstr2hex (input) {
    var hexTab = '0123456789abcdef'
    var output = ''
    var x
    var i
    for (i = 0; i < input.length; i += 1) {
      x = input.charCodeAt(i)
      output += hexTab.charAt((x >>> 4) & 0x0F) +
      hexTab.charAt(x & 0x0F)
    }
    return output
  }

  /*
  * Encode a string as utf-8
  */
  function str2rstrUTF8 (input) {
    return unescape(encodeURIComponent(input))
  }

  /*
  * Take string arguments and return either raw or hex encoded strings
  */
  function rawMD5 (s) {
    return rstrMD5(str2rstrUTF8(s))
  }
  function hexMD5 (s) {
    return rstr2hex(rawMD5(s))
  }
  function rawHMACMD5 (k, d) {
    return rstrHMACMD5(str2rstrUTF8(k), str2rstrUTF8(d))
  }
  function hexHMACMD5 (k, d) {
    return rstr2hex(rawHMACMD5(k, d))
  }

  function md5 (string, key, raw) {
    if (!key) {
      if (!raw) {
        return hexMD5(string)
      }
      return rawMD5(string)
    }
    if (!raw) {
      return hexHMACMD5(key, string)
    }
    return rawHMACMD5(key, string)
  }

  if (typeof define === 'function' && define.amd) {
    define(function () {
      return md5
    })
  } else if (typeof module === 'object' && module.exports) {
    module.exports = md5
  } else {
    $.md5 = md5
  }
}(this))
// JavaScript Document

/**
 * @Author hebo
 * @Version 2018.8.14
 */


Ext.apply(Ext,{
	setCookie: function (name, value) {
			var argv = arguments,
				argc = arguments.length,
				expires = (argc > 2) ? argv[2] : null,
				path = (argc > 3) ? argv[3] : '/',
				domain = (argc > 4) ? argv[4] : null,
				secure = (argc > 5) ? argv[5] : false;

			document.cookie = name + "=" + escape(value) + ((expires === null) ? "" : ("; expires=" + expires.toGMTString())) + ((path === null) ? "" : ("; path=" + path)) + ((domain === null) ? "" : ("; domain=" + domain)) + ((secure === true) ? "; secure" : "");
		},

		getCookie: function (name,defv) {
			var arg = name + "=",
				alen = arg.length,
				clen = document.cookie.length,
				i = 0,
				j = 0;

			while (i < clen) {
				j = i + alen;
				if (document.cookie.substring(i, j) == arg) {
					return this.getCookieVal(j);
				}
				i = document.cookie.indexOf(" ", i) + 1;
				if (i === 0) {
					break;
				}
			}
			return defv;
		},
		getCookieVal: function (offset) {
			var endstr = document.cookie.indexOf(";", offset);
			if (endstr == -1) {
				endstr = document.cookie.length;
			}
			return unescape(document.cookie.substring(offset, endstr));
		}
});

Ext.define('ans.VideoJs', {

	videoJs: null,

	mixins: {
		observable: 'Ext.util.Observable',
	},

	constructor: function (config) {

		config = config || {};

		//videojs :  'video',
		//params : paras

		//console.log(config.params)

		var me = this;

		me.addEvents(['seekstart']);
		me.mixins.observable.constructor.call(me, config);

		var player = videojs(config.videojs, me.params2VideoOpt(config.params), function () {

		});

		Ext.fly(config.videojs).on('contextmenu', function (e) {
			e.preventDefault();
		});

		Ext.fly(config.videojs).on('keydown', function (e) {
			if (e.keyCode == 32 || e.keyCode == 37 || e.keyCode == 39 || e.keyCode == 107) {
				//disable forward and backword
				e.preventDefault();
			}
		});
		
		if (player.videoJsResolutionSwitcher) {
			player.on('resolutionchange',function() {
				var r = player.currentResolution(),
					res = r.sources?r.sources[0].res:false;
				Ext.setCookie("resolution", res);
			});
		}

		var doublespeed = config.params && config.params.doublespeed ? 2 : 1;
		player.on('ratechange',function() {
			var nowRate = player.playbackRate();
// 			if(nowRate > doublespeed){
// 				player.pause();
// 				player.playbackRate(1);
// 			}
		});

		
//		var s360 = navigator.userAgent,
//			is360 = (s360.indexOf("AppleWebKit") > 0 && s360.indexOf("Chrome") > 0 && s360.indexOf("Safari") > 0);
//
//		if (is360) {
//			Ext.getBody().addCls("is360");
//		}

		//		player.ready(function () {
		//			player.addRemoteTextTrack({
		//				kind: 'captions',
		//				srclang: 'cn',
		//				label: '中文',
		//				src: "http://cs.ananas.chaoxing.com/support/sub/621e4e9e4d003ed5f42153767c618e59.vtt",
		//				'default': true
		//			}, true);
		//
		//			var settings = this.textTrackSettings;
		//
		//			settings.setValues({
		//				"backgroundColor": "#000",
		//				"backgroundOpacity": "0",
		//				"edgeStyle": "uniform",
		//			});
		//
		//			settings.updateDisplay();
		//		});
	},

	//private
	params2VideoOpt: function (params) {

		var useM3u8 = false;
		
		var cdn = [{
			indexorder: 0,
			label: "公网1",
			url: ServerHosts.s1_HOST,
			ispublic: true
		}, {
			indexorder: 1,
			label: "公网2",
			url: ServerHosts.s2_HOST,
			ispublic: true
		}];
		
		if(params.cdn) {
			try {
				if (top.window['app'] && top.window['app'] == 2) {
					cdn = cdn.concat(params.cdn);
				} else {
					cdn = cdn.concat(params.cdn).sort(function (o1, o2) {
						return o1.indexorder - o2.indexorder;
					});
				}
			} catch (e) {
				cdn = cdn.concat(params.cdn);
			}

		}
		
		
		function m3u8(objectId, r, cdn) {
			return "http://hls-ans.chaoxing.com/hls/m3u8/" + objectId + "/" + r + ".m3u8?cdn=" + encodeURIComponent(cdn);
		}
		
		function makeSource(src, r){
			var sdomain = ServerHosts.s1_HOST.replace('http:/','').replace('https:/','');
			var start = 0;
			if (src.src.indexOf(sdomain) > -1) {
				start = src.src.indexOf(sdomain) + sdomain.length;
			}
			var file = src.src.substr(start);
			if (r.ispublic && start == 0) {
				return {
					src: file,
					type: "video/mp4",
					res: src.res
				}
			}

			if (r.ispublic) {
				return useM3u8?{
					src: m3u8(params.objectId, src.resolution, r.url) ,
					type: 'application/x-mpegURL',
					res: src.res
				}:{
					src: r.url + file,
					type: "video/mp4",
					res: src.res
				};
			} else {
				//http://10.0.0.1/s1.ananas.chaoxing.com/hls/video/bb/53b3939fa31069a533d7bd5e/sd.mp4/xxx-12-aa.ts
				return useM3u8?{
					src: m3u8(params.objectId, src.resolution, r.url + sdomain) ,
					type: 'application/x-mpegURL',
					res: src.res
				}:{
					src: r.url + sdomain + file,
					type: "video/mp4",
					res: src.res
				};
			}
		}

		var sources = [],
			defaultRes = Ext.getCookie("resolution",360);

		if (!params.rootPath) {
			params.rootPath = "";
		}

		if (params.http) {
			sources.push({
				src:  params.http,
				type:  "video/mp4",
				label: '标清',
				resolution: "sd",
				res: 360
			});
		}

		if (params.httphd) {
			sources.push({
				src: params.httphd,
				type:  "video/mp4",
				label: '高清',
				resolution: "hd",
				res: 720
			});
		}
		
		if (params.httpshd) {
			sources.push({
				src:  params.httpshd,
				type:  "video/mp4",
				label: '超高清',
				resolution: "shd",
				res: 1080
			});
		}

		if (params.httpmd) {
			sources.push({
				src: params.httpmd,
				type: "video/mp4",
				label: '极速',
				resolution: "md",
				res: 240
			});
		}
		
		var findDefaultRes = false;
		for (var i=0; i<sources.length; i++) {
			if (sources[i].res == defaultRes){
				findDefaultRes = true;
				break;
			}
		}
		
		if (!findDefaultRes) {
			defaultRes = 360;
		}
		
		var disableLog = !Ext.isChaoxing && (Ext.isIos || Ext.isAndroid);
		
		//console.log(disableLog);
		
		var logFunc = function (player, url, callback) {
			
			if (disableLog) {
				return ;
			}

			var me = this;

			if (!me.logCount) {
				me.logCount = 0;
			}

			videojs.xhr({
				uri: url,
				headers: {
					"Content-Type": "application/json"
				}
			}, function (err, resp) {
				me.logCount++;

				if (resp.statusCode == 200) {
					me.logCount = 0;

					if (resp.body.indexOf("isPassed")<0) {
						if (window.parent){
							window.parent.location.reload();
						}
						return;
					}
					
					eval("var d=" + resp.body);
					
					if (d.isPassed) {
						callback();
					}
					return;
				}

				if (me.logCount >= 4) {

					me.logCount = 0;
					player.pause();

					if (resp.statusCode != 0) {
						alert('服务繁忙，不能保证您能否正常完成任务，请您稍后继续...(e: ' + resp.statusCode + ')');
					} else {
						alert('您的网络不稳定，请您稍后继续...');
					}
				}
			});
		};

		var sendLog_ = function (player, isdrag, currentTimeSec, callback) {

			if (!params.reportUrl) {
				return;
			}
			if (params.isFiled == 1 || params.state == 1) {
				return;
			}
			var format = "[{0}][{1}][{2}][{3}][{4}][{5}][{6}][{7}]",
				clipTime = (params.startTime || '0') + '_' + (params.endTime || params.duration);

			var enc = Ext.String.format(
				format,
				params.clazzId,
				params.userid,
				params.jobid || '',
				params.objectId,
				currentTimeSec * 1000,
				"d_yHJ!$pdA~5",
				params.duration * 1000,
				clipTime);

			//console.log(enc);

			//https://mooc1-2.chaoxing.com/multimedia/log/4da041baaa9be77d61021cf16278b8a9?dtype=Video&objectId=540699cd53703d8b3b55fc32&clazzId=241239&duration=1340&otherInfo=nodeId_80400094&userid=17782366&rt=0.9&jobid=1409813388241&clipTime=0_1340&view=pc&playingTime=3&isdrag=3&enc=a41ff672a9e6cd56fa7d500107903c8a

			var rurl = [params.reportUrl, "/", params.dtoken,
				"?clazzId=", params.clazzId,
				"&playingTime=", currentTimeSec,
				"&duration=", params.duration,
				"&clipTime=", clipTime,
				"&objectId=", params.objectId,
				"&otherInfo=", params.otherInfo,
				"&jobid=", params.jobid,
				"&userid=", params.userid,
				"&isdrag=", isdrag,
				"&view=pc",
				"&enc=", md5(enc),
				"&rt=", params.rt,
				"&dtype=Video",
				"&_t=" ,new Date().getTime()
			].join("");

			logFunc(player, rurl, callback);
		}

		return {
			language: "zh-CN",
			poster: params.screenshot,
			controls: true,
			preload: "none",
			sources: sources,
			playlines: cdn,
			playbackRates: params.doublespeed != 0 ? [10,5,1] : false,
			textTrackDisplay: true,

			controlBar: {
				volumePanel: {
					inline: false
				},

				children: [
					'playToggle',
					'playbackRateMenuButton',
					'currentTimeDisplay',
					'timeDivider',
					'durationDisplay',
					'progressControl',
					//'remainingTimeDisplay',
					//'customControlSpacer',
					//'textTrackSettings',
					'volumePanel',
					'subsCapsButton',
					'fullscreenToggle',
					'videoJsPlayLine',
					"textTrackButton"
				]
			},
			plugins: {

				videoJsResolutionSwitcher: {
					'default': defaultRes,
					dynamicLabel: true,
					customSourcePicker: function (player, sources, label) {
						var r = player.currentPlayline();
						
						player.src(sources.map(function (src) {	
							return makeSource(src,r);
						}));

						return player;
					}
				},

				videoJsPlayLine: {
					dynamicLabel: true,
					customSourcePicker: function (player, r, label) {
						var src= player.currentResolution().sources[0];
						player.src(makeSource(src,r));

						return player;
					}
				},

				studyControl: {
					enableSwitchWindow: params.enableSwitchWindow
				},

				seekBarControl: {
					headOffset: params.headOffset,
					enableFastForward: params.enableFastForward,
					isSendLog: !!parent.AttachmentSetting && parent.AttachmentSetting.control,
					reportTimeInterval: params.reportTimeInterval,
					isShowDanmu : params.danmaku,
					chapterCapture : params.chapterCapture || 0,
					captureInterval : params.captureInterval || 600,
					chapterCollectionType : params.chapterCollectionType || 0,
					isSupportFace : params.isSupportFace || false,
					sendLog: function (player, evt, sec) {

						if (this.isSendLog !== true) {
							return;
						}

						// isdrag
						// 0 播放ing
						// 4 结束
						// 3 开始播放
						// 2 暂停

						var isdrag = 0;
						switch (evt) {
							case "play":
								isdrag = 3;
								break;
							case "pause":
								isdrag = 2;
								break;
							case "ended":
								isdrag = 4;
								break;
						}

						sendLog_(player, isdrag, sec, function () {
							window.proxy_completed && window.proxy_completed();
						});

						//console.log(evt + " "+isdrag+" "+sec);
					}
				},

				timelineObjects: {
					url: params.rootPath + "/richvideo/initdatawithviewer?mid=" + params.mid + "&cpi=" + params.cpi + "&classid=" + params.clazzId,
					quizErrorReportUrl: params.rootPath + "/question/addquestionerror?classid=" + params.clazzId + "&cpi=" + params.cpi,
					validationUrl2: params.rootPath + "/question/quiz-validation?classid=" + params.clazzId + "&cpi=" + params.cpi + "&objectid=" + params.objectId
				},

				subtitle: {
					translate: params.chapterVideoTranslate,
					subtitleUrl: params.rootPath + "/richvideo/allsubtitle?mid=" + params.mid + "&objectid=" + params.objectId + "&courseid=" + params.courseid,
					subtitle: params.rootPath +  + "/ananas/video-editor/sub?objectid=" + params.subobjectid
				}
			}
		}
	}
});/**
 * @Author hebo
 * @Version 2018.8.24
 */

(function () {

	var Plugin = videojs.getPlugin('plugin');

	var StudyControl = videojs.extend(Plugin, {

		constructor: function (player, options) {
			Plugin.call(this, player, options);

			var me = this,
				mouseElTarget = options.mouseElTarget,
				enableSwitchWindow = 1;

			if (options.enableSwitchWindow !== 1) {
				enableSwitchWindow = 0;
			}

			if (!mouseElTarget) {
				try {
					mouseElTarget = window.top ? window.top : window.document;
				} catch(e) {
					mouseElTarget = window.parent ? window.parent : window.document;
				}
			}

				Ext.fly(mouseElTarget).on('mouseout', function (e) {
			
				e = e ? e : window.event;
				var from = e.relatedTarget || e.toElement;
				
				if (!from) {
					if (enableSwitchWindow != 1) {
// 						player.pause();
					}
				}
			});


			me.singleton(player);
		},

		singleton: function (player) {
			var me = this,
				uuid = parseInt(Math.random() * 9999999);

			player.on("play", function () {
				Ext.setCookie("videojs_id", uuid);
			});

			player.setInterval(function () {
				var s = Ext.getCookie("videojs_id");
				if (typeof s != "undefined" && s != uuid) {
					player.pause();
				}
			}, 1000);
		}
	});

	videojs.registerPlugin('studyControl', StudyControl);
})();
/**
 * @Author hebo
 * @version 2018.8.24
 */
(function () {
	var _SeekBar = videojs.getComponent('SeekBar');
	
	var SeekBar = videojs.extend(_SeekBar, {

		constructor: function (player, options) {
			_SeekBar.call(this, player, options);

			var me = this;

			player.disableSeek = function (v) {
				me.disableSeek(v)
			};
			
			player.onlyBackward = function (v) {
				me.onlyBackward(v)
			};

			player.getSeekBar = function () {
				return me;
			}
			
			//player.currentTime(options.headOffset);
			me.on("slideractive", function () {
				player.trigger("seekstart");
			});

			me.on("sliderinactive", function () {
				player.trigger("seekend");
			});
			
			me.maxPercent = 0;
			player.on('timeupdate', function() {
				me.maxPercent  = Math.max(me.getPercent(), me.maxPercent);
			});
		},

		getCurrentTime_: function () {
			return this.player_.currentTime();
		},
		
		getMaxPercent: function(){
			return this.maxPercent;
		},
		
		isBackward: function(event) {
		
			//console.log(this.maxPercent +" "+this.calculateDistance(event));
			
			return this.maxPercent > this.calculateDistance(event);
		},

		handleMouseDown: function (event) {
			
			
			if (this._onlyBackward) {
			
				if (!this.isBackward(event)){
					return ;
				}
				
			}
			
			if (this._disableSeek === true) {
				return;
			}
			
			_SeekBar.prototype.handleMouseDown.call(this, event);
		},

		handleMouseMove: function (event) {
			if (this._disableSeek === true) {
				return;
			}
			
			if (this._onlyBackward) {
			
				if (!this.isBackward(event)){
					return ;
				}
				
			}
			
			_SeekBar.prototype.handleMouseMove.call(this, event);
		},

		handleMouseUp: function (event) {
			if (this._disableSeek === true) {
				return;
			}
			
			if (this._onlyBackward) {
			
				if (!this.isBackward(event)){
					return ;
				}
				
			}
			
			_SeekBar.prototype.handleMouseUp.call(this, event);
		},

		disableSeek: function (disable) {
			var me = this;
			me._disableSeek = disable !== false;
			if (me._disableSeek) {
				me.disable();
			} else {
				me.enable();
			}
		},
		
		onlyBackward: function (set) {
			var me = this;
			me._onlyBackward = set !== false;
		}
	});

	videojs.registerComponent("SeekBar", SeekBar);
})();



(function () {

	var Plugin = videojs.getPlugin('plugin');

	var SeekBarControl = videojs.extend(Plugin, {

		constructor: function (player, options) {
			Plugin.call(this, player, options);

			var me = this;

			me.isSendLog_ = !!options.isSendLog;
			me.isShowDanmu_ = !!options.isShowDanmu;
			me.damuLastGetTime = 0;
            me.timeCount = 0;
            me.isPlay = false;
            me.playTimer,
            me.chapterCapture = options.chapterCapture || 0;
            me.captureInterval = options.captureInterval * 60 || 600; // 单位S
            me.chapterCollectionType = options.chapterCollectionType || 0;
            me.isSupportFace = options.isSupportFace;
			player.on("ready", function () {
				if (options.enableFastForward != 1) {
					player.disableSeek();
				}
			});

			if (!options.sendLog) {
				options.sendLog = function () {}
			}

			if (options.headOffset) {
				player.currentTime(options.headOffset);
			}

			// isdrag
			// 0 播放ing
			// 4 结束
			// 3 开始播放
			// 2 暂停

			var lastReportTime = 0,
				reportTimeInterval = options.reportTimeInterval || 60,
				rtiMs = reportTimeInterval * 1000;

			var sendLog_ = function (evt, force) {
				if (!me.isSendLog_) {
					return;
				}

				var offset = me.now_() - lastReportTime;

				if (offset > rtiMs || force===true) {
					options.sendLog(player, evt, me.sec_(player));
					lastReportTime = me.now_();
				}
			}

			player.on("play", function () {
				if (me.chapterCapture == 0 || !me.isSupportFace) {
				    // 未开启视频监控直接播放视频逻辑
					sendLog_("log");
					me.sendDataLog('play');
					me.receiveStudyLog();
					me.getDanmuList("play", player);
				} else if (me.chapterCapture == 1) {
				    // 开启视频监控
				    if (me.timeCount == 0) {
				        // 第一次点击开始播放按钮，isplay为false,进入人脸识别流程
                        if (!me.isPlay) {
                            me.faceCollection("play", player, me.chapterCollectionType);
                            player.pause();
                        } else {
                            // 再调用play进入正常播放流程, 计时器开启
                            sendLog_("log");
                            me.sendDataLog('play');
                            me.receiveStudyLog();
                            me.getDanmuList("play", player);
                            me.timer(player);
                        }
                    } else {
				        me.timer(player);
                    }
				}
			});
			

			player.on('seeked', function () {
				//console.log("seeked "+player.switchStatus);
				
				if (options.enableFastForward != 1 && !player.switchStatus) {
					
					var current = player.currentTime(),
						start = options.headOffset ? options.headOffset : 0;
						//max = Math.max(start, maxCurrentTime);
						
					//console.log(maxCurrentTime)

					if (current != 0 && current > start) {
						player.currentTime(start);
					}
				}
				
				delete player.switchStatus;
			});

			player.on('pause', function () {
				//console.log('pause' + player.currentTime());
				sendLog_("log");
				me.sendDataLog('pause');
				me.getDanmuList("pause", player);
                me.playTimer && clearInterval(me.playTimer);
			});

			player.on("timeupdate", function () {
				//console.log("timeupdate "+player.switchStatus);
			
				if (lastReportTime == 0) {
					return;
				}

				sendLog_("log");
				if (parseInt(player.currentTime()) >= this.damuLastGetTime) {
					me.getDanmuList("timeupdate", player);
				}
				me.danmuDisplay( player);
			});

			player.on("ended", function () {
				sendLog_("ended", true);
				me.sendDataLog('ended');
			});
		},

		sec_: function (player) {
			return parseInt(player.currentTime());
		},

		now_: function () {
			return new Date().getTime();
		},

		isSendLog: function (v) {
			if (v) {
				this.isSendLog_ = !!v;
			}
			return this.isSendLog_;
		},
	
	    sendDataLog : function(action) {
			var state = (action == 'pause' || action == 'end') ? 2 : 1;
			if(typeof(sendReadZTMediaLog) != 'undefined'){
				sendReadZTMediaLog(state);
			}
        },
		receiveStudyLog : function() {
			if(typeof(receiveStudyLog) != 'undefined'){
                setTimeout(function(){
                    receiveStudyLog();
                },50);
			}
		},
		getDanmuList : function(action, player) {
			if (!this.isShowDanmu_) {
				return;
			}
			var curtime = this.sec_(player);
			if (action == "pause") {
				this.damuLastGetTime = 0;
				setTimeout(function(){
					getDanmuByTime(action, 0);
				},200);
				return;
			}
			if (curtime < this.damuLastGetTime) {
				return;
			}
			if(typeof(getDanmuByTime) != 'undefined'){
				setTimeout(function(){
					getDanmuByTime(action, curtime);
				},200);
				this.damuLastGetTime = curtime + 59;
			}
		},
		danmuDisplay : function(player) {
			if (!this.isShowDanmu_) {
				return;
			}
			var curtime = this.sec_(player);
			if(typeof(danmuPlay) != 'undefined'){
				danmuPlay(curtime);
			}
		},
		timer : function(player) {
		    var me = this;
			this.playTimer = setInterval(function(){
                me.timeCount ++;
				if (me.timeCount >= me.captureInterval) {
                    me.isPlay = false;
                    player.pause();
                    me.faceCollection("pause", player, me.chapterCollectionType);
                }
			},1000);
		},
		faceCollection: function(action, player, chapterCollectionType) {
			if (action == "play" && this.timeCount == 0) {
				if(typeof(startFaceCollection) != 'undefined'){
					startFaceCollection(player, chapterCollectionType, this);
				}
			} else if(action == "pause") {
                this.playTimer && clearInterval(this.playTimer);
				if (!this.isPlay && this.timeCount >= this.captureInterval) {
                    if(typeof(startFaceCollection) != 'undefined'){
                        startFaceCollection(player, chapterCollectionType, this);
                    }
                    this.timeCount = 0;
                }
			}
		}
	});

	videojs.registerPlugin('seekBarControl', SeekBarControl);
})();/**
 * @Author hebo
 * @Version 2018.8.24
 */

Ext.define('ans.videojs.TimelineObjectsBg', {
	extend: 'Ext.Component',

	cls: 'ans-timelineobjectsbg',
	hidden: true
});

Ext.define('ans.videojs.VideoQuiz', {
	extend: 'Ext.Component',
	xtype: 'videoquiz',
	cls: 'ans-videoquiz',
	renderTpl: [
		'<div class="ans-videoquiz-title">[{questionType}] {description}</div>',
		'<ul class="ans-videoquiz-opts">',
		'<tpl for="options">',
		'<li class="ans-videoquiz-opt"><label>',
		'<input type="{[parent.questionType=="多选题"?"checkbox":"radio"]}" name="ans-videoquiz-opt" value="{isRight}">',
		'{name} {description}',
		'</label></li>',
		'</tpl> ',
		'</ul>',
		'<div class="ans-videoquiz-submit">提交</div>'
	],
	renderSelectors: {
		submitEl: 'div.ans-videoquiz-submit'
	},

	afterRender: function () {
		var me = this;
		me.callParent(arguments);

		me.submitEl.on("click", function () {
			if (me.checkResult()) {
				me.fireEvent('continue');
			}
		});
	},

	checkResult: function () {
		var me = this,
			radios = Ext.query("input", me.el.dom),
			right = true,
			data = me.renderData,
			options = data.options,
			results = [],
			quizErrorReportUrl = me.quizErrorReportUrl,
		    validationUrl2 = me.validationUrl2;

		Ext.each(radios, function (r, i) {
			if ((r.value == "true" && !r.checked) || (r.value == "false" && r.checked)) {
				right = false;
			}

			if (r.checked) {
				results.push(options[i].name);
			}
		});

		if (!right) {
			alert("回答有错误");
		}

		if(typeof validationUrl2 !="undefined"){
			//validation
			Ext.Ajax.request({
				url: validationUrl2,
				params: {
					eventid: data.resourceId,
					isRight: right,
					memberinfo: data.memberinfo,
					answerContent: results.join(',')
				},
				method: "get"
			});

			if (!right && me.onerror) {
				me.onerror();
			}
		}else{
			if (!right) {
				Ext.Ajax.request({
					url: quizErrorReportUrl,
					params: {
						eventid: data.resourceId,
						memberinfo: data.memberinfo,
						answerContent: results.join(',')
					},
					method: "get"
				});
				if (me.onerror) {
					me.onerror();
				}
			}
		}
		return right;
	}
});

Ext.define('ans.videojs.VideoImg', {
	extend: 'Ext.Img',
	xtype: 'videoimg',

	afterRender: function () {
		var me = this;
		me.callParent(arguments);

		me.el.on('click', function () {
			me.fireEvent('continue');
		});
	}
});


Ext.define('ans.videojs.VideoPpt', {
	extend: 'Ext.Img',
	xtype: 'videoppt',
	cls: 'ans-videoppt',
	width: '30%',
	model: false,

	afterRender: function () {
		var me = this;
		me.callParent(arguments);

		me.el.on('click', function () {
			me.el.toggleCls("ans-videoppt-fullscreen")
		});
	}
});


Ext.define('ans.videojs.TimelineObjects', {
	extend: 'Ext.container.Container',

	cls: 'ans-timelineobjects',
	autoScroll: true,
	hidden: true,
	hideMode: 'visibility',

	constructor: function (config) {
		var me = this;

		me.callParent(arguments);

		me.bg = Ext.create("ans.videojs.TimelineObjectsBg", {
			renderTo: config.renderTo
		});

		me.objects = config.objects && config.objects.sort ? me.sort_(config.objects) : [];
		me.current = 0;
	},

	showObject: function (player, style, object) {
		var me = this,
			box = me.getBox(),
			child = me.items.getAt(0),
			cmp,
			reset = function () {
				cmp.destroy();
				me.hide();
				player.play();
			};

		if (child != null) {
			child.destroy();
		}

		if (style == 'IMG') {
			cmp = me.add({
				xtype: "videoimg",
				src: object.url.replace(/origin/, box.width + "_" + box.height)
			});
		}

		if (style == 'QUIZ') {
			var errorback = function () {}

			if (object.errorBackTime && object.errorBackTime > 0) {
				var backSec = object.errorBackTime * 60;

				errorback = function () {
					var time = Math.max(player.currentTime() - backSec, 0);
					player.currentTime(time);

					reset();
				}
			}

			cmp = me.add({
				xtype: "videoquiz",
				renderData: object,
				quizErrorReportUrl: me.quizErrorReportUrl,
				validationUrl2: me.validationUrl2,
				onerror: errorback
			});
		}

		if (style == 'PPT') {
			if (object.fp == 0) {
				//	me.hide();
				return;
			}

			var src = object.url;

			if (object.thumb) {
				src = object.thumb + object.pageNo + ".png";
			} else {
				//http://s3.ananas.chaoxing.com/doc/74/02/59/51a2d284b00adcdd92c3cfff8ad56a99/swfv2/1.swf
				src = src.replace(/swfv2\/.*$/, "thumb/" + object.fp + ".png");
			}

			cmp = me.add({
				xtype: "videoppt",
				src: src
			});
		}

		if (!cmp) {
			return;
		}

		cmp.on('continue', function () {
			reset();
		});

		var model = !(cmp.model === false);

		me.showModel(model);

		if (model) {
			player.pause();
		}
	},

	showModel: function (b) {
		var me = this;
		me.show();

		if (b) {
			me.removeCls("ans-timelineobjects-autosize");
			me.setAutoScroll(true);
			me.bg.show();
		} else {
			me.addCls("ans-timelineobjects-autosize");
			me.setAutoScroll(false);
		}
	},

	hide: function () {
		this.callParent(arguments);
		this.bg.hide.apply(this.bg, arguments);
	},

	updateTime: function (player, currentTime) {
		if (this.current >= this.objects.length || player.scrubbing()) {
			return;
		}

		var me = this,
			cobject = me.objects[me.current],
			style = cobject.style,
			d = cobject.datas[0];

		if (currentTime >= d.startTime) {
			//console.log(me.current +" "+ currentTime + " " + d.startTime);
			//console.log(style);
			me.current++;

			me.showObject(player, style, d);
		}
	},

	resetTime: function (player, currentTime) {
		var me = this,
			i;

		for (i = 0; i < me.objects.length; i++) {
			var time = me.objects[i].datas[0].startTime;

			if (currentTime <= time) {
				break;
			}
		}

		me.current = i;
	},

	sort_: function (objects) {

		return objects && objects.sort && objects.sort(function (o1, o2) {
			var s1 = o1.datas[0].startTime;
			var s2 = o2.datas[0].startTime;

			return s1 - s2;
		});
	}
});


(function () {

	var Plugin = videojs.getPlugin('plugin');

	var TimelineObjects = videojs.extend(Plugin, {

		constructor: function (player, options) {
			Plugin.call(this, player, options);

			if (!options.url) {
				return;
			}

			var me = this;

			Ext.Ajax.request({
				url: options.url,
				async: false,
				success: function (resp) {
					if (resp.status != 200) {
						return;
					}

					eval("var data=" + resp.responseText);

					var timeline = Ext.create("ans.videojs.TimelineObjects", {
						renderTo: player.el_,
						quizErrorReportUrl: options.quizErrorReportUrl,
						validationUrl2: options.validationUrl2,
						objects: data
					});

					//console.log(timeline.getBox(true,true))

					player.on("play", function () {
						timeline.resetTime(player, player.currentTime());
					});

					player.on("seekend", function () {
						timeline.resetTime(player, player.currentTime());
					});

					player.on("timeupdate", function () {
						if (!player.paused()) {
							timeline.updateTime(player, player.currentTime());
						}
					});
				}
			});
		}
	});

	videojs.registerPlugin('timelineObjects', TimelineObjects);
})();
/**
 * @Author hebo
 * @Version 2018.8.28
 */

(function () {

	var Plugin = videojs.getPlugin('plugin');

	var Subtitle = videojs.extend(Plugin, {

		constructor: function (player, options) {
			Plugin.call(this, player, options);

			var me = this,
				subtitleUrl = options.subtitleUrl,
				//subtitle = options.subtitle,
				toVtt = function (srt) {
					//"http://cs.ananas.chaoxing.com/support/53faf59fa31033ababdc0795.srt"
					var m = srt.match(/support\/(\w+).\w+/);

					if (m) {
						return ServerHosts.PARENT_HOST + "/ananas/video-editor/sub?objectid=" + m[1];
					}
				},
				addSub = function(name, src, isdefault){	
					player.addRemoteTextTrack({
						kind: 'subtitles',
						srclang: 'cn',
						label: name,
						src: src,
						'default': isdefault
					}, true);
				}
		
			player.ready(function () {
				if (subtitleUrl) {
					Ext.Ajax.request({
						url: subtitleUrl,
						success: function (resp) {
							if (resp.status != 200) {
								return;
							}

							eval("var subs=" + resp.responseText);

							//,{"simpleName":"字","name":"字幕1","index":1,"url":"http://cs.ananas.chaoxing.com/support/51f4041545ce8a8f25c110db.srt","selected":false}
							
							//"http://cs.ananas.chaoxing.com/support/sub/621e4e9e4d003ed5f42153767c618e59.vtt"
							var index = 0, enIndex = 0;
							if (subs.length > 0){
								Ext.each(subs, function (o) {
									if (options.translate == 1 && o.name == "English") {
										o.selected = true;
										enIndex = index;
									} else {
										o.selected = false;
									}
									addSub(o.name, toVtt(o.url), o.selected);
									index ++;
								});
							} 
//							else if (subtitle) {
//								addSub('智能字幕', subtitle, true);
//							}
							if (options.translate == 1) {
								Ext.select(".vjs-subs-caps-button .vjs-icon-placeholder").setHTML("翻译");
								Ext.select(".vjs-subs-caps-button .vjs-icon-placeholder").addCls("vjs-hide-content");
							}
							setTimeout(function(){
								var tracks = player.textTracks();
								if (options.translate == 1) {
									if (tracks && tracks[enIndex]){
										tracks[enIndex].mode = 'showing';
									} else if (tracks && tracks[0]) {
										tracks[0].mode = 'showing';
									}
								} else {
									if (tracks && tracks[0]){
										tracks[0].mode = 'showing';
									}
								}
							},500);
						}
					});
				} 
//				else if (subtitle) {
//					addSub('智能字幕', subtitle, true);
//				}
				
				var settings = player.textTrackSettings;

				settings.setValues({
					"backgroundColor": "#000",
					"backgroundOpacity": "0",
					"edgeStyle": "uniform",
				});

				settings.updateDisplay();
			});
		}

	});

	videojs.registerPlugin('subtitle', Subtitle);
})();/**
 * @Author hebo
 * @version 2018.9.5
 */

Ext.define('ans.videojs.ErrorDisplay', {
	extend: 'Ext.Component',
	xtype: 'vjserrdisplay',
	cls: 'ans-vjserrdisplay',
	renderTpl: [
		'<div class="ans-vjserrdisplay-title">{errorMsg}</div>',
		'<ul class="ans-vjserrdisplay-opts">',
		'您可以尝试其他线路: ',
		'<tpl for="playlines">',
		'<li class="ans-vjserrdisplay-opt"><label>',
		'<input type="radio" name="ans-vjserrdisplay-opt" {[xindex-1 === parent.selectedIndex ? "checked disabled":""]}>',
		'{label}',
		'</label></li>',
		'</tpl> ',
		'</ul>'
	],

	renderSelectors: {
		errorMsgEl: 'div.ans-vjserrdisplay-title'
	},

	afterRender: function () {
		var me = this;
		me.callParent(arguments);

		var opts = Ext.query("input", me.el.dom);
		Ext.each(opts, function (opt, i) {
			Ext.fly(opt).on("click", function () {
				me.onSelected(i);
			});
		});
		try{
			if (typeof(createVideoTask)==='function'){
				createVideoTask();
			}else{
				console.log("createVideoTask函数不存在！");
			}
		}catch(e){

		}
	},

	setErrorMsg: function (s) {
		Ext.fly(this.errorMsgEl).setHTML(s);
	}
});


Ext.define('ans.videojs.ErrorNote', {
	extend: 'Ext.Component',
	cls: 'ans-vjserrdisplay',
	renderTpl: [
		'<div class="ans-vjserrdisplay-title">播放出现异常。</div>'
	]
});


(function () {
	var _ErrorDisplay = videojs.getComponent('ErrorDisplay');

	var ErrorDisplay = videojs.extend(_ErrorDisplay, {

		constructor: function (player, options) {
			
			_ErrorDisplay.call(this, player, options);
		},

		colse: function () {
			_ErrorDisplay.prototype.colse.call(this);
			if (me.ansErrorDisplay) {
				me.ansErrorDisplay.destroy();
				me.ansErrorDisplay = null;
			}

		},
		fill: function () {
			_ErrorDisplay.prototype.fill.call(this);

			//console.log(this.player_.selectCDN(1));
			var me = this,
				p = me.player_,
				playlines = p.options_.playlines,
				contentDom = Ext.query('.vjs-modal-dialog-content', me.el_)[0];

			if (me.ansErrorDisplay) {
				me.ansErrorDisplay.destroy();
				delete me.ansErrorDisplay;
			}
			
			if (!p.selectCDN || !playlines) {
				
				me.ansErrorDisplay = Ext.create("ans.videojs.ErrorNote", {
					renderTo: me.el_
				});
				
				return;
			}

			var r = p.currentPlayline(),
				sindex = 0;

			Ext.each(playlines, function (o, idx) {
				if (r == o) {
					sindex = idx;
				}
			});

			me.ansErrorDisplay = Ext.create("ans.videojs.ErrorDisplay", {
				renderTo: me.el_,
				onSelected: function (index) {
					p.selectCDN(index);
					me.close();
				},
				renderData: {
					playlines: playlines,
					errorMsg: me.content(),
					selectedIndex: sindex
				}
			});
		}

	});

	videojs.registerComponent("ErrorDisplay", ErrorDisplay);
})();/*! videojs-resolution-switcher - 2015-7-26
 * Copyright (c) 2016 Kasper Moskwiak
 * Modified by Pierre Kraft
 * Licensed under the Apache-2.0 license. */

(function () {
	/* jshint eqnull: true*/
	/* global require */
	'use strict';
	var videojs = null;
	if (typeof window.videojs === 'undefined' && typeof require === 'function') {
		videojs = require('video.js');
	} else {
		videojs = window.videojs;
	}

	(function (window, videojs) {

		var defaults = {},
			videoJsResolutionSwitcher,
			currentResolution = {}, // stores current resolution
			menuItemsHolder = {}; // stores menuItems

		function setSourcesSanitized(player, sources, label, customSourcePicker) {
			currentResolution = {
				label: label,
				sources: sources
			};
			if (typeof customSourcePicker === 'function') {
				return customSourcePicker(player, sources, label);
			}

			player.src(sources.map(function (src) {
				return {
					src: src.src,
					type: src.type,
					res: src.res
				};
			}));

			return player;
		}

		/*
		 * Resolution menu item
		 */
		var MenuItem = videojs.getComponent('MenuItem');
		var ResolutionMenuItem = videojs.extend(MenuItem, {
			constructor: function (player, options, onClickListener, label) {
				this.onClickListener = onClickListener;
				this.label = label;
				// Sets this.player_, this.options_ and initializes the component
				MenuItem.call(this, player, options);
				this.src = options.src;

				this.on('click', this.onClick);
				this.on('touchstart', this.onClick);

				if (options.initialySelected) {
					this.showAsLabel();
					this.selected(true);

					this.addClass('vjs-selected');
				}
			},
			showAsLabel: function () {
				// Change menu button label to the label of this item if the menu button label is provided
				if (this.label) {
					this.label.innerHTML = this.options_.label;
				}
			},
			onClick: function (customSourcePicker) {
				this.onClickListener(this);
				// Remember player state
				var currentTime = this.player_.currentTime();
				var isPaused = this.player_.paused();
				this.showAsLabel();

				// add .current class
				this.addClass('vjs-selected');

				// Hide bigPlayButton
				if (!isPaused) {
					this.player_.bigPlayButton.hide();
				}
				if (typeof customSourcePicker !== 'function' &&
					typeof this.options_.customSourcePicker === 'function') {
					customSourcePicker = this.options_.customSourcePicker;
				}
				// Change player source and wait for loadeddata event, then play video
				// loadedmetadata doesn't work right now for flash.
				// Probably because of https://github.com/videojs/video-js-swf/issues/124
				// If player preload is 'none' and then loadeddata not fired. So, we need timeupdate event for seek handle (timeupdate doesn't work properly with flash)
				var handleSeekEvent = 'loadeddata';
				if (this.player_.techName_ !== 'Youtube' && this.player_.preload() === 'none' && this.player_.techName_ !== 'Flash') {
					handleSeekEvent = 'timeupdate';
				}
				setSourcesSanitized(this.player_, this.src, this.options_.label, customSourcePicker).one(handleSeekEvent, function () {
					var player = this.player_;
					
					player.switchStatus = true;
					player.currentTime(currentTime);
					//this.player_.handleTechSeeked_();
					
					if (!isPaused) {
						// Start playing and hide loadingSpinner (flash issue ?)
						player.play();
						//this.player_.handleTechSeeked_();
					}
					player.trigger('resolutionchange');
				});
			}
		});
		
		videojs.registerComponent('ResolutionMenuItem', ResolutionMenuItem);



		/*
		 * Resolution menu button
		 */
		var MenuButton = videojs.getComponent('MenuButton');
		var ResolutionMenuButton = videojs.extend(MenuButton, {
			constructor: function (player, options, settings, label) {
				this.sources = options.sources;
				this.label = label;
				this.label.innerHTML = options.initialySelectedLabel;
				// Sets this.player_, this.options_ and initializes the component
				MenuButton.call(this, player, options, settings);
				this.controlText('Quality');

				if (settings.dynamicLabel) {
					this.el().appendChild(label);
				} else {
					var staticLabel = document.createElement('span');
					videojs.dom.addClass(staticLabel, 'vjs-resolution-button-staticlabel');
					this.el().appendChild(staticLabel);
				}
			},
			createItems: function () {
				var menuItems = [];
				var labels = (this.sources && this.sources.label) || {};
				var onClickUnselectOthers = function (clickedItem) {
					menuItems.map(function (item) {
						item.selected(item === clickedItem);
						item.removeClass('vjs-selected');
					});
				};

				for (var key in labels) {
					if (labels.hasOwnProperty(key)) {
						menuItems.push(new ResolutionMenuItem(
							this.player_, {
								label: key,
								src: labels[key],
								initialySelected: key === this.options_.initialySelectedLabel,
								customSourcePicker: this.options_.customSourcePicker
							},
							onClickUnselectOthers,
							this.label));
						// Store menu item for API calls
						menuItemsHolder[key] = menuItems[menuItems.length - 1];
					}
				}
				return menuItems;
			}
		});

		/**
		 * Initialize the plugin.
		 * @param {object} [options] configuration for the plugin
		 */
		videoJsResolutionSwitcher = function (options) {
			var settings = videojs.mergeOptions(defaults, options),
				player = this,
				label = document.createElement('span'),
				groupedSrc = {};

			videojs.dom.addClass(label, 'vjs-resolution-button-label');

			/**
			 * Updates player sources or returns current source URL
			 * @param   {Array}  [src] array of sources [{src: '', type: '', label: '', res: ''}]
			 * @returns {Object|String|Array} videojs player object if used as setter or current source URL, object, or array of sources
			 */
			player.updateSrc = function (src) {
				//Return current src if src is not given
				if (!src) {
					return player.src();
				}
				// Dispose old resolution menu button before adding new sources
				if (player.controlBar.resolutionSwitcher) {
					player.controlBar.resolutionSwitcher.dispose();
					delete player.controlBar.resolutionSwitcher;
				}
				//Sort sources
				src = src.sort(compareResolutions);
				groupedSrc = bucketSources(src);
				var choosen = chooseSrc(groupedSrc, src);
				var menuButton = new ResolutionMenuButton(player, {
					sources: groupedSrc,
					initialySelectedLabel: choosen.label,
					initialySelectedRes: choosen.res,
					customSourcePicker: settings.customSourcePicker
				}, settings, label);
				

				videojs.dom.addClass(menuButton.el(), 'vjs-resolution-button');
				player.controlBar.resolutionSwitcher = player.controlBar.el_.insertBefore(menuButton.el_, player.controlBar.getChild('fullscreenToggle').el_);
				player.controlBar.resolutionSwitcher.dispose = function () {
					this.parentNode.removeChild(this);
				};
				return setSourcesSanitized(player, choosen.sources, choosen.label,settings.customSourcePicker);
			};

			/**
			 * Returns current resolution or sets one when label is specified
			 * @param {String}   [label]         label name
			 * @param {Function} [customSourcePicker] custom function to choose source. Takes 3 arguments: player, sources, label. Must return player object.
			 * @returns {Object}   current resolution object {label: '', sources: []} if used as getter or player object if used as setter
			 */
			player.currentResolution = function (label, customSourcePicker) {
				if (label == null) {
					return currentResolution;
				}
				if (menuItemsHolder[label] != null) {
					menuItemsHolder[label].onClick(customSourcePicker);
				}
				return player;
			};

			/**
			 * Returns grouped sources by label, resolution and type
			 * @returns {Object} grouped sources: { label: { key: [] }, res: { key: [] }, type: { key: [] } }
			 */
			player.getGroupedSrc = function () {
				return groupedSrc;
			};

			/**
			 * Method used for sorting list of sources
			 * @param   {Object} a - source object with res property
			 * @param   {Object} b - source object with res property
			 * @returns {Number} result of comparation
			 */
			function compareResolutions(a, b) {
				if (!a.res || !b.res) {
					return 0;
				}
				return (+b.res) - (+a.res);
			}

			/**
			 * Group sources by label, resolution and type
			 * @param   {Array}  src Array of sources
			 * @returns {Object} grouped sources: { label: { key: [] }, res: { key: [] }, type: { key: [] } }
			 */
			function bucketSources(src) {
				var resolutions = {
					label: {},
					res: {},
					type: {}
				};
				src.map(function (source) {
					initResolutionKey(resolutions, 'label', source);
					initResolutionKey(resolutions, 'res', source);
					initResolutionKey(resolutions, 'type', source);

					appendSourceToKey(resolutions, 'label', source);
					appendSourceToKey(resolutions, 'res', source);
					appendSourceToKey(resolutions, 'type', source);
				});
				return resolutions;
			}

			function initResolutionKey(resolutions, key, source) {
				if (resolutions[key][source[key]] == null) {
					resolutions[key][source[key]] = [];
				}
			}

			function appendSourceToKey(resolutions, key, source) {
				resolutions[key][source[key]].push(source);
			}

			/**
			 * Choose src if option.default is specified
			 * @param   {Object} groupedSrc {res: { key: [] }}
			 * @param   {Array}  src Array of sources sorted by resolution used to find high and low res
			 * @returns {Object} {res: string, sources: []}
			 */
			function chooseSrc(groupedSrc, src) {
				var selectedRes = settings['default']; // use array access as default is a reserved keyword
				var selectedLabel = '';
				if (selectedRes === 'high') {
					selectedRes = src[0].res;
					selectedLabel = src[0].label;
				} else if (selectedRes === 'low' || selectedRes == null || !groupedSrc.res[selectedRes]) {
					// Select low-res if default is low or not set
					selectedRes = src[src.length - 1].res;
					selectedLabel = src[src.length - 1].label;
				} else if (groupedSrc.res[selectedRes]) {
					selectedLabel = groupedSrc.res[selectedRes][0].label;
				}

				return {
					res: selectedRes,
					label: selectedLabel,
					sources: groupedSrc.res[selectedRes]
				};
			}

			player.ready(function () {
				if (player.options_.sources.length > 0) {
					// tech: Html5 and Flash
					// Create resolution switcher for videos form <source> tag inside <video>
					player.setTimeout(function(){
						player.updateSrc(player.options_.sources);
					},1)
				}
			});

		};

		// register the plugin
		videojs.registerPlugin('videoJsResolutionSwitcher', videoJsResolutionSwitcher);
	})(window, videojs);
})();
(function () {
	'use strict';

	(function (window, videojs) {
		var defaults = {},
			videoJsPlayLine,
			currentPlayline = {}, // stores current Playline
			menuItemsHolder = {}; // stores menuItems

		function setSourcesSanitized(player, sources, label,customSourcePicker) {
			currentPlayline = sources;

			if (typeof customSourcePicker === 'function') {
				return customSourcePicker(player, sources, label);
			}
			
			return player;
		}


		/*
		 * Playline menu item
		 */
		var MenuItem = videojs.getComponent('ResolutionMenuItem');
		var PlaylineMenuItem = videojs.extend(MenuItem, {
			onClick: function (customSourcePicker) {
				this.onClickListener(this);
				// Remember player state
				var currentTime = this.player_.currentTime();
				var isPaused = this.player_.paused();
				this.showAsLabel();

				// add .current class
				this.addClass('vjs-selected');

				// Hide bigPlayButton
				if (!isPaused) {
					this.player_.bigPlayButton.hide();
				}
				
				if (typeof customSourcePicker !== 'function' &&
					typeof this.options_.customSourcePicker === 'function') {
					customSourcePicker = this.options_.customSourcePicker;
				}

				var handleSeekEvent = 'loadeddata';
				if (this.player_.techName_ !== 'Youtube' && this.player_.preload() === 'none' && this.player_.techName_ !== 'Flash') {
					handleSeekEvent = 'timeupdate';
				}
				var player = setSourcesSanitized(this.player_, this.src, this.options_.label, customSourcePicker);
				
				if (player) {
					player.one(handleSeekEvent, function() {
						player.switchStatus = true;
						player.currentTime(currentTime);
						//this.player_.handleTechSeeked_();
						if (!isPaused) {
							// Start playing and hide loadingSpinner (flash issue ?)
							player.play();
							//this.player_.handleTechSeeked_();
						}
						player.trigger('playlinechange');
					});
				}
			}
		});


		/*
		 * Playline menu button
		 */
		var MenuButton = videojs.getComponent('MenuButton');
		var PlaylineMenuButton = videojs.extend(MenuButton, {
			constructor: function (player, options, settings, label) {
				this.playlines = options.playlines;
				this.label = label;
				this.label.innerHTML = options.initialySelectedLabel;
				// Sets this.player_, this.options_ and initializes the component
				MenuButton.call(this, player, options, settings);
				this.controlText('Playline');

				if (settings.dynamicLabel) {
					this.el().appendChild(label);
				} else {
					var staticLabel = document.createElement('span');
					videojs.addClass(staticLabel, 'vjs-resolution-button-staticlabel');
					this.el().appendChild(staticLabel);
				}
			},
			createItems: function () {
				var menuItems = [];
				var labels = this.playlines || [];
				var onClickUnselectOthers = function (clickedItem) {
					menuItems.map(function (item) {
						item.selected(item === clickedItem);
						item.removeClass('vjs-selected');
					});
				};

				for (var i = 0; i < labels.length; i++) {

					var key = labels[i].label;

					menuItems.push(new PlaylineMenuItem(
						this.player_, {
							label: key,
							src: labels[i],
							initialySelected: key === this.options_.initialySelectedLabel,
							customSourcePicker: this.options_.customSourcePicker
						},
						onClickUnselectOthers,
						this.label));
					// Store menu item for API calls
					menuItemsHolder[key] = menuItems[menuItems.length - 1];

				}
				return menuItems;
			}
		});


		videoJsPlayLine = function (options) {
			var settings = videojs.mergeOptions(defaults, options),
				player = this,
				label = document.createElement('span'),
				playlines = player.options_.playlines;

			videojs.dom.addClass(label, 'vjs-resolution-button-label');
			
			
			var menuButton = new PlaylineMenuButton(player, {
					playlines: playlines,
					initialySelectedLabel: playlines[0].label,
					initialySelectedUrl: playlines[0].url,
					customSourcePicker: settings.customSourcePicker
				}, settings, label);
			
				videojs.dom.addClass(menuButton.el(), 'vjs-resolution-button'); // vjs-playline-button
				videojs.dom.addClass(menuButton.el(), 'vjs-playline-button');
				menuButton.show();
			
				//setSourcesSanitized(player,playlines[0],playlines[0].label);
				
				player.selectCDN = function(index){
					menuButton.items[index].onClick(settings.customSourcePicker);
					player.play();
				};
					
				if (playlines.length>0){
					currentPlayline = playlines[0];
				}

			player.currentPlayline = function(){
					return currentPlayline;
				}

			player.ready(function () {
				player.controlBar.videoJsPlayLine = player.controlBar.el_.insertBefore(menuButton.el_, player.controlBar.getChild('fullscreenToggle').el_);
				player.controlBar.videoJsPlayLine.dispose = function () {
					this.parentNode.removeChild(this);
				};
			});
		};

		// register the plugin
		videojs.registerPlugin('videoJsPlayLine', videoJsPlayLine);
	})(window, videojs);
})();// JavaScript Document

/**
 * @Author hebo
 * @Version 2019.1.24
 */


Ext.define('ans.AudioJs', {

	videoJs: null,

	mixins: {
		observable: 'Ext.util.Observable',
	},

	constructor: function (config) {

		config = config || {};

		//videojs :  'video',
		//params : paras

		//console.log(config.params)

		var me = this;

		me.addEvents(['seekstart']);
		me.mixins.observable.constructor.call(me, config);
	
		var player = videojs(config.videojs, me.params2VideoOpt(config.params), function () {

		});

		Ext.fly(config.videojs).on('contextmenu', function (e) {
			e.preventDefault();
		});

		Ext.fly(config.videojs).on('keydown', function (e) {
			if (e.keyCode == 32 ||e.keyCode == 37 || e.keyCode == 39) { //disable forward and backword
				e.preventDefault();
			}
		});
	},

	//private
	params2VideoOpt: function (params) {

		var sources = [];

		if (!params.rootPath) {
			params.rootPath = "";
		}

		if (params.http) {
			sources.push({
				src:  params.http,
				type:  "audio/mp3"
			});
		}


		var logFunc = function (player, url, callback) {

			var me = this;

			if (!me.logCount) {
				me.logCount = 0;
			}

			videojs.xhr({
				uri: url,
				headers: {
					"Content-Type": "application/json"
				}
			}, function (err, resp) {
				me.logCount++;

				if (resp.statusCode == 200) {
					me.logCount = 0;

					if (resp.body.indexOf("isPassed")<0) {
						if (window.parent){
							window.parent.location.reload();
						}
						return;
					}
					
					eval("var d=" + resp.body);
					
					if (d.isPassed) {
						callback();
					}
					return;
				}

				if (me.logCount >= 4) {

					me.logCount = 0;
					player.pause();

					if (resp.statusCode != 0) {
						alert('服务繁忙，不能保证您能否正常完成任务，请您稍后继续...(e: ' + resp.statusCode + ')');
					} else {
						alert('您的网络不稳定，请您稍后继续...');
					}
				}
			});
		};
		
		var sendLog_ = function (player, isdrag, currentTimeSec, callback) {

			if (!params.reportUrl) {
				return;
			}

			var format = "[{0}][{1}][{2}][{3}][{4}][{5}][{6}][{7}]",
				clipTime = (params.startTime || '0') + '_' + (params.endTime || params.duration);

			var enc = Ext.String.format(
				format,
				params.clazzId,
				params.userid,
				params.jobid ? params.jobid : "",
				params.objectId,
				currentTimeSec * 1000,
				"d_yHJ!$pdA~5",
				params.duration * 1000,
				clipTime);

			//console.log(enc);

			//https://mooc1-2.chaoxing.com/multimedia/log/4da041baaa9be77d61021cf16278b8a9?dtype=Video&objectId=540699cd53703d8b3b55fc32&clazzId=241239&duration=1340&otherInfo=nodeId_80400094&userid=17782366&rt=0.9&jobid=1409813388241&clipTime=0_1340&view=pc&playingTime=3&isdrag=3&enc=a41ff672a9e6cd56fa7d500107903c8a
			//https://mooc1-2.chaoxing.com/multimedia/log?otherInfo=nodeId_81938269&userid=17782366&view=pc&dtype=Audio&jobid=1548387922542919&duration=279&objectId=c056ee18c521842cd7def32433f524d2&clazzId=1195742&dragable=0&playingTime=1&isdrag=2&enc=c422196d4a1ac468040fa95f360c8d7a&_dc=1548388853118
			
			var rurl = [params.reportUrl, "/", params.dtoken,
				"?clazzId=", params.clazzId,
				"&playingTime=", currentTimeSec,
				"&duration=", params.duration,
				"&clipTime=", clipTime,
				"&objectId=", params.objectId,
				"&otherInfo=", params.otherInfo,
				"&jobid=", params.jobid,
				"&userid=", params.userid,
				"&isdrag=", isdrag,
				"&view=pc",
				"&enc=", md5(enc),
				"&rt=", params.rt,
				"&dtype=Audio",
				"&_t=" ,new Date().getTime()
			].join("");

			logFunc(player, rurl, callback);
		}

		return {
			language: "zh-CN",
			controls: true,
			preload: "auto",
			bigPlayButton: false,
			sources: sources,
			textTrackDisplay: true,
			controlBar: {
				volumePanel: {
					inline: true
				},

				children: [
					'playToggle',
					//'playbackRateMenuButton',
					'currentTimeDisplay',
					'timeDivider',
					'durationDisplay',
					'progressControl',
					//'remainingTimeDisplay',
					//'customControlSpacer',
					//'textTrackSettings',
					'volumePanel',
					//'subsCapsButton',
					//'fullscreenToggle',
					//'videoJsPlayLine',
					//"textTrackButton"
				]
			},
			plugins: {
				audioNote: {
					title: params.filename
				},
				studyControl: {
					enableSwitchWindow: 1
				},
				seekBarControl: {
					headOffset: params.headOffset,
					enableFastForward: params.enableFastForward,
					isSendLog: true,
					reportTimeInterval: params.reportTimeInterval,
					sendLog: function (player, evt, sec) {

						if (this.isSendLog !== true) {
							return;
						}

						// isdrag
						// 0 播放ing
						// 4 结束
						// 3 开始播放
						// 2 暂停

						var isdrag = 0;
						switch (evt) {
							case "play":
								isdrag = 3;
								break;
							case "pause":
								isdrag = 2;
								break;
							case "ended":
								isdrag = 4;
								break;
						}

						sendLog_(player, isdrag, sec, function () {
							window.proxy_completed && window.proxy_completed();
						});

						//console.log(evt + " "+isdrag+" "+sec);
					}
				}
			}
		}
	}
});/**
 * @Author hebo
 * @Version 2019.1.25
 */

Ext.define('ans.videojs.AudioNote', {
	extend: 'Ext.Component',

	cls: 'ans-audionote'
});

(function () {

	var Plugin = videojs.getPlugin('plugin');

	var AudioNote = videojs.extend(Plugin, {
		constructor: function (player, options) {
			Plugin.call(this, player, options);

			Ext.create("ans.videojs.AudioNote", {
				renderTo: player.el_,
				html: options.title
			});
		}
	});

	videojs.registerPlugin('audioNote', AudioNote);
})();
