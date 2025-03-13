// $Id: $
(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() : // No I18N
    typeof define === 'function' && define.amd ? define('security',[],factory) : // No I18N
      (global.ZASEC = factory());
}(this, (function () { 'use strict'; // No I18N

  /**
   * Polyfills
   */

  /**
   *
   * It's a wrapper over Object.defineProperty for setting  data descriptors for object .A data descriptor is a property that has a value, which sets isWritable,isConfigurable,isEnumerable for an object. By default all configuration values are false.
   *
   * Below function will define Object.defineProperty if not defined.
   * Normal property addition through assignment(=) creates properties.
   * But it shows up during property enumeration (for...in loop or Object.keys method), whose values may be changed or deleted.
   * And it may even create some unusual behaviour. The Object.defineProperty method allows
   * three extra details(configurable, writable, and enumerable) to be set for the value.
   * By default all the value are true. Since defineProperty is not supported
   * below IE-9 we have implemented fall back to directly assign value to the object
   *
   * @param   {Object} obj
   * @param   {string} property
   * @param   {value}  value
   * @param   {boolean}  isOverrideDefaultValue
   * @param   {boolean}  isWritable
   * @param   {boolean}  isConfigurable
   * @param   {boolean}  isEnumerable
   * @returns {Object}
   */
  /* eslint-disable-next-line max-params */
  function defineProperty(obj, property, value, isOverrideDefaultValue, isWritable, isConfigurable, isEnumerable) {
    if (!isOverrideDefaultValue && property in obj) {
      return;
    }
    if (!Object.defineProperty || !function () {
      try {
        Object.defineProperty({}, 'x', {}); // No I18N
        return true;
      } catch (e) {
        return false;
      }
    }()) {
      obj[property] = value;
      return obj;
    }

    isWritable = isWritable === true;
    isConfigurable = isConfigurable === true;
    isEnumerable = isEnumerable === true;
    return Object.defineProperty(obj, property, {
      value: value,
      writable: isWritable,
      configurable: isConfigurable,
      enumerable: isEnumerable
    });
  }

  /**
   * Defining String.prototype.codePointAt if not defined already
   * This is not supported in IE 11 and below
   */


  /**
   * Defining String.fromCodePoint if not defined already
   * Which is not supported in many browsers like IE ,Android ,Opera Mobile
   * */

  /**
   * @author: Patrick-2626 & Vigneshwar-5036
   *
   * @wiki: https://intranet.wiki.zoho.com/security/client-side-security.html
   *
   * Reference
   *  1)https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/
   *  2)https://github.com/danielstjules/blankshield
   */

  var ZASEC$1 = window && window.ZASEC ? window.ZASEC : { version: '5.4.0' };

  if (!ZASEC$1.defineProperty) {
    ZASEC$1.defineProperty = defineProperty;
  }

  if (!ZASEC$1['5.4.0']) {
    ZASEC$1['5.4.0'] = {
      version: '5.4.0',
      defineProperty: defineProperty
    };
  }

  /** @format */

  var APP_AGENT_CONF_PROMISE = null;
  var CSRF_DETAILS_PROMISE = null;
  var CSRF_PROP_NAME = "csrf"; // No I18N
  var CSRF_PARAM_PROP_NAME = "param_name"; // No I18N
  var CSRF_COOKIE_PROP_NAME = "cookie_name"; // No I18N
  var WAF_APP_AGENT_CONFIG_URL = "/waf/appAgentConf"; // No I18N
  var REUSE_KEY;
  var TimeDiff = null;
  /**
   * Load App Agent Conf, primarily used now for getting CSRF info
   * As of now, this call will not be made. We are only using this to get CSRF param and cookie names
   * which are currently set by user using setCSRF.
   * But it might be used for other purposes in the future, and we will mandate getting this info
   * through the /waf call. So keeping this implementation for now.
   *
   * Response will be like:
   *   {
   *     csrf: {
   *       param_name: "ac_p"
   *       cookie_name: "_ca"
   *     }
   *   }
   * @return {Promise<Response>}
   */
  function loadAppAgentConf() {

    if (APP_AGENT_CONF_PROMISE) {
      return APP_AGENT_CONF_PROMISE;
    }
    APP_AGENT_CONF_PROMISE = fetch(WAF_APP_AGENT_CONFIG_URL).catch(function (error) {
      throw Error("Error while fetching App Agent Conf: " + error); // No I18N
    });
    return APP_AGENT_CONF_PROMISE;
  }

  /**
   * Usage is like this:
   *    ZASEC.configuration.setCSRF({
   *      paramName: "_ca",
   *      cookieName: "ac_p"
   *    })
   * @param config
   */
  function setCSRF(config) {
    if (config.paramName && config.cookieName) {
      CSRF_DETAILS_PROMISE = Promise.resolve([config.paramName, config.cookieName]);
    }
  }

  function getCSRFDetails() {
    if (CSRF_DETAILS_PROMISE) {
      return CSRF_DETAILS_PROMISE;
    }
    CSRF_DETAILS_PROMISE = this.loadAppAgentConf().then(function (response) {
      return response.json().then(function (jsonResponse) {
        var csrfParamName = jsonResponse && jsonResponse[CSRF_PROP_NAME] && jsonResponse[CSRF_PROP_NAME][CSRF_PARAM_PROP_NAME];
        if (!csrfParamName) {
          throw Error("Invalid CSRF Param Name in Conf"); // No I18N
        }
        var csrfCookieName = jsonResponse && jsonResponse[CSRF_PROP_NAME] && jsonResponse[CSRF_PROP_NAME][CSRF_COOKIE_PROP_NAME];
        if (!csrfCookieName) {
          throw Error("Invalid CSRF Cookie Name in Conf"); // No I18N
        }
        return [csrfParamName, csrfCookieName];
      });
    });
    return CSRF_DETAILS_PROMISE;
  }

  function getCSRFName() {
    return getCSRFDetails().then(function (response) {
      return response[0];
    });
  }

  function getCSRFValue() {
    return getCSRFDetails().then(function (response) {
      return response[1];
    });
  }

  var configuration = {
    setCSRF: setCSRF,
    getCSRFName: getCSRFName,
    getCSRFValue: getCSRFValue,
    getCSRFDetails: getCSRFDetails,
    loadAppAgentConf: loadAppAgentConf
  };

  if (Object.freeze) {
    Object.freeze(configuration);
  }

  if (ZASEC$1.version === '5.4.0' && !ZASEC$1.configuration) {
    ZASEC$1.defineProperty(ZASEC$1, 'configuration', // No I18N
      configuration, true, false, false, true);
  }
  if (!ZASEC$1['5.4.0'].configuration) {
    ZASEC$1.defineProperty(ZASEC$1['5.4.0'], 'configuration', // No I18N
      configuration, true, false, false, true);
  }

  var _createClass = function () {
    function defineProperties(target, props) {
      for (var i = 0; i < props.length; i++) {
        var descriptor = props[i];
        descriptor.enumerable = descriptor.enumerable || false;
        descriptor.configurable = true;
        if ("value" in descriptor) { // No I18N
          descriptor.writable = true;
        }
        Object.defineProperty(target, descriptor.key, descriptor);
      }
    }
    return function (Constructor, protoProps, staticProps) {
      if (protoProps) {
        defineProperties(Constructor.prototype, protoProps);
      }
      if (staticProps) {
        defineProperties(Constructor, staticProps);
      }
      return Constructor;
    };
  }();

  function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } } // No I18N

  /** @format */
var _createClass$1 = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck$1(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }// No I18N

var Logger = function () {
  function Logger(level) {
    _classCallCheck$1(this, Logger);

    this.LEVELS = {
      NONE: -1,
      DEBUG: 0,
      INFO: 1,
      WARN: 2,
      ERROR: 3
    };
    if (level === this.LEVELS.NONE || level === this.LEVELS.DEBUG || level === this.LEVELS.INFO || level === this.LEVELS.WARN || level === this.LEVELS.ERROR) {
      this.level = level;
    } else {
      this.level = this.LEVELS.ERROR;
    }
  }

  _createClass$1(Logger, [{
    key: "debug",// No I18N
    value: function debug() {
      var _window;
      for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
        args[_key] = arguments[_key];
      }
    }
  }, {
    key: "info",// No I18N
    value: function info() {
      var _window2;

      for (var _len2 = arguments.length, args = Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
        args[_key2] = arguments[_key2];
      }

    }
  }, {
    key: "warn",// No I18N
    value: function warn() {
      var _window3;

      for (var _len3 = arguments.length, args = Array(_len3), _key3 = 0; _key3 < _len3; _key3++) {
        args[_key3] = arguments[_key3];
      }

    }
  }, {
    key: "error",// No I18N
    value: function error() {
      var _window4;


      for (var _len4 = arguments.length, args = Array(_len4), _key4 = 0; _key4 < _len4; _key4++) {
        args[_key4] = arguments[_key4];
      }

    }
  }]);

  return Logger;
}();

function extend(obj, mixin, isDeep, isDeepMixArray) {
  if (!mixin) {
    return obj;
  }
  var keys = Object.keys(mixin);
  if (!keys.length) {
    return obj;
  }
  var _iteratorNormalCompletion = true;
  var _didIteratorError = false;
  var _iteratorError = undefined;

  try {
    for (var _iterator = keys[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
      var key = _step.value;

      var v2 = mixin[key];
      if (obj[key] === undefined) {
        obj[key] = mixin[key];
      } else if (isDeep) {
        var v1 = obj[key];
        if (is(v1, Object) && is(v2, Object)) {
          extend(v1, v2, isDeep, isDeepMixArray);
        } else if (isDeepMixArray && is(v1, Array) && is(v2, Array)) {
          obj[key] = v1.concat(v2);
        }
      }
    }
  } catch (err) {
    _didIteratorError = true;
    _iteratorError = err;
  } finally {
    try {
      if (!_iteratorNormalCompletion && _iterator.return) {
        _iterator.return();
      }
    } finally {
      if (_didIteratorError) {
        throw _iteratorError;
      }
    }
  }

  return obj;
}

var defaultConfig = {
  algorithm: "RSA-OAEP", // No I18N
  key_hash: "SHA-256", // No I18N
  key_size: 2048,
  key_encoding: "Base64", // No I18N
  transmission_algorithm: "AES-GCM", // No I18N

  publicKeyFormat: "spki", // No I18N
  privateKeyFormat: "pkcs8", // No I18N
  transmission_key_length: 256,
  transmission_iv_length: 12,

  logLevel: 3
};
  function _encrypt(data, keyIV, publicKey) {
    var encryptPromise = encryptAgent.encrypt(data, keyIV).then(function (_ref) {
      var key = _ref.key,
          data = _ref.data;

      return encryptAgent.encryptSymmetricKeyAndIV(key, publicKey).then(function (encryptedKeyData) {
        var exportedBinaryDataAndKey = encryptAgent.exportBinary([encryptedKeyData, data]);
        return {
          key: exportedBinaryDataAndKey[0],
          data: exportedBinaryDataAndKey[1]
        };
      });
    });
    return encryptPromise.then(function (result) {
      encryptAgent.logger.debug("Encryption complete: ", data); // No I18N
      return result;
    }).catch(function (error) {
      throw Error("Error while encrypting data: " + error); // No I18N
    });
  }
  var PayloadEncryptAgent = function () {
    function PayloadEncryptAgent(config) {
      _classCallCheck(this, PayloadEncryptAgent);
      
		config = extend(config || {}, defaultConfig);
		this.KEY_USAGES = {
			ENCRYPT: "encrypt", // No I18N
			DECRYPT: "decrypt" // No I18N
		};
		this.asymmetricEncryptionAlgorithm = config.algorithm;
   		this.asymmetricEncryptionHash = config.key_hash;
   		this.asymmetricPublicKeyFormat = config.publicKeyFormat;
		this.keyEncryptionAlgorithm = "AES-GCM"; // No I18N
		this.keyLength = 256;
		this.symmetricKeyEncryptionAlgorithm = config.transmission_algorithm;
		this.symmetricKeyLength = config.transmission_key_length;
		this.symmetricKeyIVLength = config.transmission_iv_length;
		this.logger = new Logger(config.logLevel);
    }
    /**
     * Convert a Base64 String to Uint8Array
     * @param {String} base64string
     * @returns {Uint8Array}
     */


    _createClass(PayloadEncryptAgent, [{
      key: "base64ToUint8Array", // No I18N
      value: function base64ToUint8Array(base64string) {
        var binaryString = window.atob(base64string);
        var bytes = new Uint8Array(binaryString.length);
        for (var i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
      }

      /**
       * Convert a Uint8Array to Base64 String
       * @param {Uint8Array} uint8array
       * @returns {String}
       */

    }, {
      key: "uint8ArrayToBase64", // No I18N
      value: function uint8ArrayToBase64(uint8array) {
        var binaryString = String.fromCharCode.apply(null, uint8array);
        return btoa(binaryString);
      }

      /**
       * Encrypt AESKeyIV with RSA PublicKey
       * @param {Uint8Array} aesKeyIV
       * @param {String} publicKey
       * @returns {Promise<String>}
       */

    }, {
		key: "exportBinary",// No I18N
	    value: function exportBinary(data) {
	      var _this = this;
	
	      if (data.constructor === Array) {
	        return data.map(function (eachData) {
	          return _this.exportBinary(eachData);
	        });
	      }
	      if (data.constructor === ArrayBuffer) {
	        return this.uint8ArrayToBase64(new Uint8Array(data));
	      }
	      if (data.constructor === Uint8Array) {
	        return this.uint8ArrayToBase64(data);
	      }
	      throw new Error("Data is not in Binary format!"); // No I18N
	    }
	
	    /**
	     * Normalize binary data to ArrayBuffer
	     * This would be called to normalize encrypted data or any binary data.
	     * If datatype is string, then we can assume it is base64 encoded binary data.
	     *
	     * @param {String|Uint8Array|ArrayBuffer} binaryData
	     * @return {ArrayBuffer}
	     */

	},{
      key: "encryptWithRSAPublicKey", // No I18N
      value: function encryptWithRSAPublicKey(aesKeyIV, publicKey) {
        var _this = this;

        return new Promise(function (resolve, reject) {
          var publicKeyBytes = _this.base64ToUint8Array(publicKey);
          // Import the public key
          crypto.subtle.importKey("spki", // No I18N
            publicKeyBytes.buffer, { name: "RSA-OAEP", hash: "SHA-256" }, // No I18N
            true, ["encrypt"]).then(function (key) {
            // Encrypt data using the public key
            _this.encryptData(aesKeyIV, key, { name: "RSA-OAEP" }) // No I18N
              .then(function (encryptedData) {
                resolve(encryptedData);
              }).catch(function (error) {
              reject("RSA Encryption error: " + error); // No I18N
            });
          }).catch(function (error) {
            reject("RSA Key import error: " + error); // No I18N
          });
        });
      }

      /**
       * Generate IV for AES-GCM
       * @returns {Uint8Array}
       */

    }, {
		key: "getAsymmetricEncryptionAlgorithmForUsage",// No I18N
	    value: function getAsymmetricEncryptionAlgorithmForUsage() {
	      return { name: this.asymmetricEncryptionAlgorithm };
	    }
	
	    /**
	     * Get the symmetric algorithm details for generating a new symmetric key
	     * @return {AesKeyGenParams}
	     */

	},{
      key: "generateIV",// No I18N
	    value: function generateIV() {
	      return crypto.getRandomValues(new Uint8Array(this.symmetricKeyIVLength));
	    }

    /**
     * Extract the IV bytes from the Symmetric Key Data
     * @param {Uint8Array} AESKeyArray
     * @return {Uint8Array}
     */

    }, {
      key: "exportAESKey", // No I18N
      value: function exportAESKey(key) {
        return new Promise(function (resolve, reject) {
          crypto.subtle.exportKey("raw", key) // No I18N
            .then(function (exportedKey) {
              resolve(new Uint8Array(exportedKey));
            }).catch(function (error) {
            return reject(error);
          });
        });
      }

      /**
       * Generate an AES-256 key
       * @returns {Promise<CryptoKey>}
       */

    }, {
      key: "generateAESKey", // No I18N
      value: function generateAESKey() {
        var _this2 = this;

        return new Promise(function (resolve, reject) {
          crypto.subtle.generateKey({
            name: _this2.keyEncryptionAlgorithm,
            length: _this2.keyLength
          }, true, ["encrypt"]).then(function (key) {
            resolve(key);
          }).catch(function (error) {
            return reject(error);
          });
        });
      }

      /**
       *
       * @param {Uint8Array} dataBytes
       * @param {CryptoKey} key
       * @param {RsaOaepParams,AesGcmParams} algorithm
       * @return {Promise<String>}
       */

    }, {
      key: "encryptData", // No I18N
      value: function encryptData(dataBytes, key, algorithm) {
        var _this3 = this;

        return new Promise(function (resolve, reject) {
          crypto.subtle.encrypt(algorithm, key, dataBytes).then(function (encrypted) {
            encrypted = _this3.uint8ArrayToBase64(new Uint8Array(encrypted));
            resolve(encrypted);
          }).catch(function (error) {
            return reject(error);
          });
        });
      }

      /**
       * Encrypt the given payload using AES-GCM
       * @param {String} data
       * @param {String} publicKey
       * @return {Promise<Object>}
       */

    }, {
		key: "getReusableKey",// No I18N
		value : function getReusableKey(){
			var tempvariable;
			if(isMultiData){
				tempvariable = REUSE_KEY;
			}else{
				tempvariable = encryptAgent.getSymmetricKey()
				REUSE_KEY= tempvariable;
			}
			return tempvariable;
		}
	},{
		key: "getSymmetricKey",// No I18N
		value: function getSymmetricKey(key) {
			var _this2 = this;

			var symmetricKeyPromise = void 0;
			var IVBytes = void 0;
			if (!key || key.constructor !== Object && key.constructor !== String && key.constructor !== Uint8Array && key.constructor !== ArrayBuffer) {
				symmetricKeyPromise = this.generateSymmetricKey();
				IVBytes = this.generateIV();
				symmetricKeyPromise.then(function(generatedKey) {
					_this2.logger.debug("Symmetric key generated: ", generatedKey); // No I18N
				});
			} else if (key.constructor === Object && key.key && key.key.constructor === CryptoKey && key.iv && key.iv.constructor === Uint8Array) {
				// reuse that key
				symmetricKeyPromise = Promise.resolve(key.key);
				IVBytes = key.iv;
			} else {
				var symmetricKeyArray = new Uint8Array(this.normalizeBinaryData(key));
				var symmetricKeyBytes = this.extractSymmetricKeyBytes(symmetricKeyArray);
				IVBytes = this.extractIVBytes(symmetricKeyArray);
				this.logger.debug("IV Bytes extracted: ", IVBytes); // No I18N
				symmetricKeyPromise = this.importSymmetricKey(symmetricKeyBytes);
				symmetricKeyPromise.then(function(importedKey) {
					_this2.logger.debug("Symmetric key imported: ", importedKey); // No I18N
				});
			}
			if (symmetricKeyPromise) {
				return symmetricKeyPromise.then(function(symmetricKey) {
					return {
						key: symmetricKey,
						iv: IVBytes
					};
				});
			} else {
				this.logger.error("Failed to get symmetric key!", key); // No I18N
			}
		}

		/**
		 * Import the symmetric key bytes as a usable CryptoKey
		 * @param {Uint8Array} key
		 * @return {Promise<CryptoKey>}
		 */
		
	},{
		key: "generateSymmetricKey",// No I18N
		value: function generateSymmetricKey() {
			return crypto.subtle.generateKey(this.getSymmetricEncryptionAlgorithmForGeneration(), true, [this.KEY_USAGES.ENCRYPT, this.KEY_USAGES.DECRYPT]).catch(function(error) {
				throw new Error("Failed to generate symmetric key! Error: " + error); // No I18N
			});
		}

		/**
		 * Generate a new symmetric key
		 * @param {String|Uint8Array|ArrayBuffer|Object} [key]
		 * @returns {Promise<{key:CryptoKey,iv:Uint8Array}>}
		 */

	},{
		key: "getSymmetricEncryptionAlgorithmForGeneration",// No I18N
		value: function getSymmetricEncryptionAlgorithmForGeneration() {
			return {
				name: this.symmetricKeyEncryptionAlgorithm,
				length: this.symmetricKeyLength
			};
		}

		/**
		 * Get the symmetric algorithm details for importing the symmetric key
		 * @return {AlgorithmIdentifier}
		 */
	},{
		key: "getSymmetricEncryptionAlgorithmForUsage",// No I18N
		value: function getSymmetricEncryptionAlgorithmForUsage(IVBytes) {
			return {
				name: this.symmetricKeyEncryptionAlgorithm,
				iv: IVBytes
			};
		}

		/**
		 * Generate a new asymmetric key pair
		 * @param algorithm
		 * @param keySize
		 * @returns {Promise<CryptoKeyPair>}
		 */
	},{
		key: "exportSymmetricKeyAndIV",// No I18N
		value: function exportSymmetricKeyAndIV(symmetricKey, IVBytes) {
			var _this7 = this;

			return this.exportSymmetricKey(symmetricKey).then(function(symmetricKeyBytes) {
				var keyAndIV = _this7.mergeSymmetricKeyAndIV(symmetricKeyBytes, IVBytes);
				_this7.logger.debug("Symmetric key exported: ", keyAndIV); // No I18N
				return keyAndIV;
			});
		}

		/**
		 *
		 * @param {Uint8Array} keyAndIV
		 * @param {CryptoKey} publicKey
		 * @return {Promise<ArrayBuffer>}
		 */
	},{
		key: "mergeSymmetricKeyAndIV",// No I18N
		value: function mergeSymmetricKeyAndIV(keyBytes, IVBytes) {
			if (keyBytes.constructor === ArrayBuffer) {
				keyBytes = new Uint8Array(keyBytes);
			}
			var keyAndIV;
			if(encWithTimeStamp){
				var timestamp = Date.now();
				timestamp = timestamp - (TimeDiff ? TimeDiff : difference_time);
				var high = Math.floor(timestamp / Math.pow(2, 32));
				var low = timestamp % Math.pow(2, 32);
				var buffer = new ArrayBuffer(9);
				var view = new DataView(buffer);
				view.setUint32(0, high, false);
				view.setUint32(4, low, false);
				var byteArray = new Uint8Array(buffer);
				byteArray[8] = "-".charCodeAt(0);
				var keyAndIV = new Uint8Array(byteArray.length + keyBytes.length + IVBytes.length);
				keyAndIV.set(byteArray);
				keyAndIV.set(keyBytes, byteArray.length);
				keyAndIV.set(IVBytes, byteArray.length + keyBytes.length);
			}else{
				keyAndIV = new Uint8Array(keyBytes.length + IVBytes.length);
				keyAndIV.set(keyBytes);
				keyAndIV.set(IVBytes, keyBytes.length);
			}
			
			return keyAndIV;
		}

    /**
     *
     * @param {ArrayBuffer} symmetricKeyData
     * @return {Promise<{key: CryptoKey, iv: Uint8Array}>}
     */

	},{
		key: "exportSymmetricKey",// No I18N
		value: function exportSymmetricKey(key) {
			return crypto.subtle.exportKey("raw", key) // No I18N
				.catch(function(error) {
					console.log(">>>>>>>>>Export symmetric key catch<<<<<<<<<<<<<");
					throw new Error("Failed to export symmetric key! Error: " + error); // No I18N
				});
		}

		/**
		 * Encrypt the symmetric key data with asymmetric public key
		 * @param {Uint8Array} aesKeyIV
		 * @param {CryptoKey} publicKey
		 * @returns {Promise<ArrayBuffer>}
		 */
	},{
		key: "_encrypt",// No I18N
		value: function _encrypt(data, key, algorithm) {
			var dataArrayBuffer = this.convertToBinary(data);
			return crypto.subtle.encrypt(algorithm, key, dataArrayBuffer);
		}

		/**
		 *
		 * @param {String|Uint8Array|ArrayBuffer} data
		 * @param {CryptoKey} key
		 * @param {RsaOaepParams,AesGcmParams} algorithm
		 * @return {Promise<ArrayBuffer>}
		 */

	},{
		 key: "uint8ArrayToBase64",// No I18N
	    value: function uint8ArrayToBase64(uint8array) {
	      var binaryString = "";
	      for (var i = 0; i < uint8array.length; i++) {
	        binaryString += String.fromCharCode(uint8array[i]);
	      }
	      return btoa(binaryString);
	    }
	
	    /**
	     * Convert data to binary (ArrayBuffer format)
	     * This would be called to normalize data to be encrypted,
	     * which can be normal string information or binary data like files.
	     *
	     * @param {String|Uint8Array|ArrayBuffer} data
	     * @return {ArrayBuffer}
	     */
	},{
		key: "convertToBinary",// No I18N
		value: function convertToBinary(data) {
			if (data.constructor === ArrayBuffer) {
				return data;
			}
			if (typeof data === "string") {
				// No I18N
				var dataBytes = new TextEncoder().encode(data); // Convert the given string to Uint8Array
				return dataBytes.buffer;
			}
			if (data.constructor === Uint8Array) {
				return data.buffer;
			}
			throw new Error("Data cannot be converted to Binary!"); // No I18N
		}

		/**
		 * Export binary data to binary (ArrayBuffer format)
		 * This would be called to normalize data to be encrypted,
		 * which can be normal string information or binary data like files.
		 *
		 * @param {Uint8Array | Uint8Array[] | ArrayBuffer | ArrayBuffer[]} data
		 * @return {String | String[]}
		 */
	},{
		key: "normalizeBinaryData",// No I18N
	    value: function normalizeBinaryData(binaryData) {
	      if (binaryData.constructor === ArrayBuffer) {
	        return binaryData;
	      } else if (typeof binaryData === "string") {// No I18N
	        // No I18N
	        var binaryDataArray = this.base64ToUint8Array(binaryData);
	        return binaryDataArray.buffer;
	      } else if (binaryData.constructor === Uint8Array) {
	        return binaryData.buffer;
	      }
	      throw new Error("Data cannot be normalized to Binary!"); // No I18N
	    }
	
	    /**
	     * Get the asymmetric algorithm details for importing the asymmetric key
	     * @param algorithm
	     * @param keySize
	     * @returns {RsaHashedKeyGenParams}
	     */
	},{
		key: "extractSymmetricKeyBytes",// No I18N
		value: function extractSymmetricKeyBytes(AESKeyArray) {
			return AESKeyArray.slice(0, AESKeyArray.length - this.symmetricKeyIVLength);
		}

		/**
		 * Generate a new symmetric key
		 * @returns {Promise<CryptoKey>}
		 */
	},{
	    key: "encryptSymmetricKeyAndIV",// No I18N
	    value: function encryptSymmetricKeyAndIV(keyAndIV, publicKey) {
	      var _this8 = this;
	
	      // Encrypt the key with RSA Public Key
	      return this.encryptWithPublicKey(keyAndIV, publicKey).then(function (encryptedSymmetricKey) {
	        _this8.logger.debug("Symmetric key encrypted: ", encryptedSymmetricKey); // No I18N
	        return encryptedSymmetricKey;
	      });
	    }
	
	    /**
	     *
	     * @param {String} encryptedSymmetricKey
	     * @param {CryptoKey} privateKey
	     * @return {Promise<ArrayBuffer>}
	     */
	},{
	    key: "encryptWithPublicKey",// No I18N
	    value: function encryptWithPublicKey(aesKeyIV, publicKey) {
	      var _this4 = this;
	
	      // Import the public key
	      return this.importAsymmetricPublicKey(publicKey).then(function (asymmetricKey) {
	        _this4.logger.debug("Asymmetric key imported: ", asymmetricKey); // No I18N
	        var asymmetricAlgorithm = _this4.getAsymmetricEncryptionAlgorithmForUsage();
	        // Encrypt data using the public key
	        return _this4._encrypt(aesKeyIV, asymmetricKey, asymmetricAlgorithm).catch(function (error) {
	          throw new Error("Failed to encrypt the symmetric key with asymmetric public key! Error: " + // No I18N
	          error);
	        });
	      });
	    }
	
	    /**
	     * Decrypt the symmetric key data with asymmetric private key
	     * @param {String} encryptedSymmetricKey
	     * @param {CryptoKey} privateKey
	     * @return {Promise<ArrayBuffer>}
	     */

	},{
		key: "importAsymmetricPublicKey",// No I18N
		value: function importAsymmetricPublicKey(publicKey) {
			if (publicKey === null || publicKey.constructor === CryptoKey) {
				return Promise.resolve(publicKey);
			}
			var publicKeyBuffer = this.normalizeBinaryData(publicKey);
			var algorithm = this.getAsymmetricEncryptionAlgorithmForImport();
			return crypto.subtle.importKey(this.asymmetricPublicKeyFormat, publicKeyBuffer, algorithm, true, [this.KEY_USAGES.ENCRYPT]).catch(function(error) {
				throw new Error("Failed to import Asymmetric Public Key! Algorithm: " + JSON.stringify(algorithm) + " Error: " + error);// No I18N
			});
		}

		/**
		 * Import the Asymmetric PrivateKey
		 * @param {String|Uint8Array|ArrayBuffer|CryptoKey} privateKey
		 * @returns {Promise<CryptoKey>}
		 */

	},{
		key: "extractIVBytes",// No I18N
		value: function extractIVBytes(AESKeyArray) {
			return AESKeyArray.slice(AESKeyArray.length - this.symmetricKeyIVLength);
		}

		/**
		 * Extract the key bytes from the Symmetric Key Data
		 * @param {Uint8Array} AESKeyArray
		 * @return {Uint8Array}
		 */
	},{
		key: "getAsymmetricEncryptionAlgorithmForImport",// No I18N
	    value: function getAsymmetricEncryptionAlgorithmForImport() {
	      return {
	        name: this.asymmetricEncryptionAlgorithm,
	        hash: this.asymmetricEncryptionHash
	      };
	    }
	
	    /**
	     * Get the asymmetric algorithm details for encrypting/decrypting using the asymmetric key
	     * @return {RsaOaepParams}
	     */
	},{
		key: "importSymmetricKey",// No I18N
		value: function importSymmetricKey(key) {
			var _this3 = this;

			return crypto.subtle.importKey("raw", // No I18N
				key.buffer, this.getSymmetricEncryptionAlgorithmForImport(), true, [this.KEY_USAGES.ENCRYPT, this.KEY_USAGES.DECRYPT]).catch(function(error) {
					_this3.logger.debug("Encrypted symmetric key bytes: ", key); // No I18N
					throw new Error("Failed to import symmetric key! Error: " + error);// No I18N
				});
		}

		/**
		 * Export the symmetric key
		 * @param {CryptoKey} key
		 * @returns {Promise<ArrayBuffer>}
		 */
	},{
		key: "getSymmetricEncryptionAlgorithmForImport",// No I18N
		value: function getSymmetricEncryptionAlgorithmForImport() {
			return {
				name: this.symmetricKeyEncryptionAlgorithm
			};
		}

		/**
		 * Get the symmetric algorithm details for encrypting/decrypting using the symmetric key
		 * @return {AesGcmParams}
		 */
	},{
      key: "encrypt",// No I18N
		value: function encrypt(data, symmetricKey) {
			var _this10 = this;

			this.logger.debug("Encryption started: "); // No I18N
			return this.getSymmetricKey(symmetricKey).then(function(_ref) {
				var key = _ref.key,
					iv = _ref.iv;

				var symmetricKeyAlgorithm = _this10.getSymmetricEncryptionAlgorithmForUsage(iv);
				_this10.logger.debug("Symmetric Encryption Algorithm: ", // No I18N
					symmetricKeyAlgorithm);
				return _this10.exportSymmetricKeyAndIV(key, iv).then(function(keyAndIV) {
					var dataArray = Array.isArray(data) ? data : [data];
					var promiseArray = dataArray.map(function(eachData, index) {
						_this10.logger.debug("Started encrypting data in " + index + ": ", eachData);// No I18N
						return _this10._encrypt(eachData, key, symmetricKeyAlgorithm).then(function(encryptedData) {
							_this10.logger.debug("Finished encrypting data in " + index + ": ", encryptedData);// No I18N
							return encryptedData; 
						}).catch(function(error) {
							console.log(">>>>>>>>>Encrypt Error<<<<<<<<<<<<<");
							throw new Error("Failed to encrypt the data using Symmetric Encryption: " + // No I18N
								error);
						});
					});
					return Promise.all(promiseArray).then(function(encryptedData) {
						_this10.logger.debug("Encryption finished: "); // No I18N
						return {
							key: keyAndIV,
							data: encryptedData.length === 1 ? encryptedData[0] : encryptedData
						};
					});
				});
			});
		}

		/**
		 * Decrypt the given payload using the given encrypted symmetric key
		 * @param {String|Uint8Array|ArrayBuffer|Array} encryptedData
		 * @param {ArrayBuffer} symmetricKeyData
		 * @return {Promise<ArrayBuffer|Array<ArrayBuffer>>}
		 */
    }]);

    return PayloadEncryptAgent;
  }();

  /**
   * Custom Functions for Sanitizer
   **/















  /**
   * Cookie handling functions
   **/




  function getCookie(name) {
    name = name + '=';
    var cookieList = document.cookie;
    var res = void 0;
    cookieList.split('; ').forEach(function (cookie) {
      if (decodeURIComponent) {
        cookie = decodeURIComponent(cookie);
      }
      if (cookie.indexOf(name) === 0) {
        res = cookie.substring(name.length);
      }
    });
    return res;
  }



// Unused functions
//
// function setArray(arr1, arr2){
//   arr1.splice.apply(arr1,[0,arr1.length].concat(arr2));
// }
//
// function addObjsToSet(set, set2) {
//   for (let each in set2) {
//     if (set2.hasOwnProperty(each)) {
//       set[each] = true;
//     }
//   }
//   return set;
// };
//
// function removeFromSet(set, key) {
//   delete set[key];
//   return set;
// }
//
// /* Add all object keys to array */
// function addToArr(array, set) {
//   let property;
//   for (property in set) {
//     if (set.hasOwnProperty(property)) {
//       array.push(property);
//     }
//   }
//   return array;
// }
//
// /* Add flags to config */
// function addToConfig(set, array) {
//   let l = array.length;
//   while (l--) {
//     set[array[l]] = true;
//   }
//   return set;
// }

  function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

  /** @format */

  var DEFAULT_ENCRYPTION_CONFIG = {
    DELIMITER: "-" // No I18N
  };
  var SCOPES = {
    ORG: "org", // No I18N
    COMMON: "common" // No I18N
  };
  var ORG_PUBLIC_KEY_PROMISE = null;
  var COMMON_PUBLIC_KEY_PROMISE = null;
  var WAF_ENCRYPTION_PUBLIC_KEY_URL = "/waf/getPayloadEncryptionPublicKey"; // No I18N
  /** 
   * Encrypt the given payload using AES-GCM. publicKeyData contains the keyID, followed by version and
   * publicKey. All 3 are separated by the delimiter "-".
   * Response will be a string containing the following, separated by the same delimiter "-"
   *  keyID
   *  version
   *  encryptedKey
   *  encryptedData
   *
   * @param {String} data
   * @param {String} publicKeyData
   * @param {Object} config
   *
   * @return {Promise<String>}
   */
	var encryptAgent = new PayloadEncryptAgent();
  function encrypt(data, publicKeyData) {
    var config = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};

    config = {
      delimiter: config.delimiter || DEFAULT_ENCRYPTION_CONFIG.DELIMITER
    };
    var publicKeyArray = publicKeyData.split(config.delimiter);
    var keyID = "0";
    var version = "v1";//No i18n
    var publicKey = publicKeyArray[0];
    
  return encryptAgent.getSymmetricKey().then(function(key) {
	  return _encrypt(data, key, publicKey).then(function(result) {
		  return keyID + config.delimiter + version + config.delimiter + result.key + config.delimiter + result.data;
	  });
  });
    
  }

  /**
   * Fetch the publicKeyData using Common scope and encrypt the given data
   *
   * @param {String} data
   * @param {Object} config
   *
   * @return {Promise<String>}
   */

  function encryptDataInCommonScope(data, config) {
    return getPublicKey(SCOPES.COMMON,data,config).then(function (publicKeyData) {
		var publicKeyData = JSON.parse(publicKeyData);
		CurrentTime = publicKeyData.currentTime;
		publicKeyData = publicKeyData.publicKey	;
		if(!isValid(difference_time)){
			var system_time = Date.now();
			difference_time = system_time -  CurrentTime;
		}
      return encrypt(data, publicKeyData, config);
    });
  }

  /**
   * Fetch the publicKeyData using Org scope and encrypt the given data
   *
   * @param {String} data
   * @param {Object} config
   *
   * @return {Promise<String>}
   */

  function encryptDataInOrgScope(data, config) {
    return getPublicKey(SCOPES.ORG).then(function (publicKeyData) {
      return encrypt(data, publicKeyData, config);
    });
  }

  /**
   * Fetch the publicKeyData using the given scope and encrypt the given data
   *
   * @param {String} data
   * @param {String} scope
   * @param {Object} config
   *
   * @return {Promise<String>}
   */

  function encryptData(data, scope, config) {
    scope = scope || SCOPES.COMMON;
    if (scope === SCOPES.ORG) {
      return encryptDataInOrgScope(data, config);
    } else if (scope === SCOPES.COMMON) {
      return encryptDataInCommonScope(data, config);
    } else {
      throw new Error("Unknown Scope"); // No I18N
    }
  }

  function makeitnull(value){
	COMMON_PUBLIC_KEY_PROMISE = value;
  }
  function onloadTimeDiff(){
    var system_time = Date.now();
    TimeDiff = system_time -  JSON.parse(payloadEncryptionPublicKey).currentTime;
  }
  function getPublicKey(scope) {
    if (scope === SCOPES.ORG && ORG_PUBLIC_KEY_PROMISE) {
      return ORG_PUBLIC_KEY_PROMISE;
    }
    if (scope === SCOPES.COMMON && COMMON_PUBLIC_KEY_PROMISE) {
      return COMMON_PUBLIC_KEY_PROMISE;
    }
    var PUBLIC_KEY_PROMISE = new Promise(function(resolve, reject) {
    if(typeof payloadEncryptionPublicKey != 'undefined' && payloadEncryptionPublicKey){
    resolve(payloadEncryptionPublicKey);
    
    }else{
      configuration.getCSRFDetails().then(function(detail) {
        var csrfParamName = detail[0];
        var csrfValue = getCookie(detail[1]);
        var params = "scope=" + scope + "&" + csrfParamName + "=" + csrfValue; // No I18N
        var objHTTP = xhr();
        objHTTP.open('POST', accountsPublicKeyURL, true);
        objHTTP.overrideMimeType("text/plain");// No I18N
        objHTTP.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded;charset=UTF-8');
        objHTTP.setRequestHeader('X-ZCSRF-TOKEN', csrfParamName + '=' + csrfValue);
		params = params+"&isSystemTimeNeeded=true";//No I18n
        objHTTP.onreadystatechange = function() {
          if (objHTTP.readyState == 4) {
            resolve(objHTTP.responseText.toString());
          }
        };
        objHTTP.send(params);
      }).catch(function(error) {
        reject(error); // Propagate any errors from configuration.getCSRFDetails()
      });
    }
    });
//    var PUBLIC_KEY_PROMISE = configuration.getCSRFDetails().then(function (detail) {
//      var csrfParamName = detail[0];
//      var csrfValue = getCookie(detail[1]);
//      var bodyParams = _defineProperty({
//        scope: scope
//      }, csrfParamName, csrfValue);
//      var formData = new FormData();
//      for (var key in bodyParams) {
//        formData.append(key, bodyParams[key]);
//      }
//      var params = "scope="+scope+ "&" +csrfParamName +"="+ csrfValue; // No I18N
//      var objHTTP = xhr();
//      objHTTP.open('POST', accountsPublicKeyURL, true);
//      objHTTP.setRequestHeader('Content-Type','application/x-www-form-urlencoded;charset=UTF-8');
//      objHTTP.setRequestHeader('X-ZCSRF-TOKEN',csrfParamName+'='+csrfValue);
//  objHTTP.onreadystatechange=function() {
//		if(objHTTP.readyState==4) {
//			return objHTTP.responseText.toString();
//		}
//      }
//      objHTTP.send(params);
//      return fetch(accountsPublicKeyURL, {
//        method: "POST", // No I18N
//        body: formData
//      }).then(function (response) {
//        return response.text();
//      });
//    });
    if (scope === SCOPES.ORG) {
      ORG_PUBLIC_KEY_PROMISE = PUBLIC_KEY_PROMISE;
    }
    if (scope === SCOPES.COMMON) {
      COMMON_PUBLIC_KEY_PROMISE = PUBLIC_KEY_PROMISE;
    }
    return PUBLIC_KEY_PROMISE;
  }

  var Encryption = {
    SCOPES: SCOPES,
    encryptData: encryptData,
    encryptDataInOrgScope: encryptDataInOrgScope,
    encryptDataInCommonScope: encryptDataInCommonScope,
    makeitnull : makeitnull,
    onloadTimeDiff : onloadTimeDiff
  };

  if (Object.freeze) {
    Object.freeze(Encryption);
  }

  if (ZASEC$1.version === '5.4.0' && !ZASEC$1.Encryption) {
    ZASEC$1.defineProperty(ZASEC$1, 'Encryption', // No I18N
      Encryption, true, false, false, true);
  }
  if (!ZASEC$1['5.4.0'].Encryption) {
    ZASEC$1.defineProperty(ZASEC$1['5.4.0'], 'Encryption', // No I18N
      Encryption, true, false, false, true);
  }

  return ZASEC$1;

})));


/*
  Usage:

  // Need to configure CSRF param name and cookie name to fetch the public key from WAF Agent
  ZASEC.configuration.setCSRF({
      paramName: "_pppp",
      cookieName: "_cccc"
  });

  // This will return a promise that fulfills to the following string format
  ZASEC.Encryption.encryptData("sampleData").then(response => {
    console.log(response); // <KeyID>-<Version>-<EncryptedKey>-<EncryptedData>
  });

 */
