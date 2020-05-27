/*
 Copyright 2017 IBM Corp.
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

const express = require("express");
const session = require("express-session");
const log4js = require("log4js");
const passport = require("passport");
const WebAppStrategy = require("bluemix-appid").WebAppStrategy;
const APIStrategy = require("bluemix-appid").APIStrategy;

const SelfServiceManager = require("bluemix-appid").SelfServiceManager;
const helmet = require("helmet");
const bodyParser = require("body-parser"); // get information from html forms
const flash = require("connect-flash");
const app = express();
// cfenv provides access to your Cloud Foundry environment
// for more info, see: https://www.npmjs.com/package/cfenv
const cfenv = require('cfenv');
const logger = log4js.getLogger("cloud-directory-app-sample-server");
const base64url = require("base64url");
const crypto = require("crypto");

const LANDING_PAGE_URL = "/index.html";
const CALLBACK_URL = "/ibm/cloud/appid/callback";
const LOGOUT_URL = "/ibm/cloud/appid/logout";
const ROP_LOGIN_PAGE_URL = "/ibm/cloud/appid/rop/login";
const ROP_SUBMIT = "/rop/login/submit";
const PROTECTED_ENDPOINT = "/protected";
const CHANGE_PASSWORD_PAGE = "/ibm/cloud/appid/cloudLand/view/change/password";
const CHANGE_DETAILS_PAGE = "/ibm/cloud/appid/cloudLand/view/change/details";
const GET_USER_DETAILS = "/ibm/cloud/appid/cloudLand/mobile/get_user_details";

const SIGN_UP_PAGE = "/ibm/cloud/appid/view/sign_up";
const FORGOT_PASSWORD_PAGE = "/ibm/cloud/appid/view/forgot_password";
const ON_USER_VERIFIED = "/ibm/cloud/appid/view/account_confirmed";
const ON_RESET_PASSWORD = "/ibm/cloud/appid/view/reset_password_form";
const SIGN_UP_SUBMIT = "/sign_up/submit/:platform?";
const FORGOT_PASSWORD_SUBMIT = "/forgot_password/submit/:platform?";
const RESEND = "/resend/:templateName";
const RESET_PASSWORD_SUBMIT = "/reset_password/submit/:platform?";

const CHANGE_DETAILS_SUBMIT = "/change_details/submit";
const CHANGE_DETAILS_SUBMIT_MOBILE = "/change_details/submit/mobile";

const CHANGE_PASSWORD_SUBMIT = "/change_password/submit";
const CHANGE_PASSWORD_SUBMIT_MOBILE = "/change_password/submit/mobile";

const GENERAL_ERROR = "GENERAL_ERROR";
const USER_NOT_FOUND = "userNotFound";
const MOBILE_PLATFORM = "mobile";

const loginEjs = 'login.ejs';
const signUpEjs = 'sign_up.ejs';
const forgotPasswordEjs = 'forgot_password.ejs';
const resetPasswordSentEjs = 'reset_password_sent.ejs';
const thanksForSignUpEjs = 'thanks_for_sign_up.ejs';
const signUpConfirmedEjs = 'account_confirmed.ejs';
const resetPasswordFormEjs = 'reset_password_form.ejs';
const resetPasswordExpiredEjs = 'reset_password_expired.ejs';
const resetPasswordSuccessEjs = 'reset_password_success.ejs';
const passwordChangedSuccessEjs = 'password_changed_success.ejs';
const changeDetailsEjs = 'change_details.ejs';
const changePasswordEjs = 'change_password.ejs';

const mobileSignUpConfirmation = 'cloudland.sign.up://sample.com';
const mobileResetPasswordConfirmation = 'cloudland.reset.password://sample.com';

let resetPasswordCodesMap = new Map();

app.use(helmet());
app.use(flash());
app.set('view engine', 'ejs'); // set up ejs for templating

// Setup express application to use express-session middleware
// Must be configured with proper session storage for production
// environments. See https://github.com/expressjs/session for
// additional documentation
app.use(session({
	secret: "123456",
	resave: true,
	saveUninitialized: true
}));

// serve the files out of ./public as our main files
app.use(express.static(__dirname + '/public'));
// Configure express application to use passportjs
app.use(passport.initialize());
app.use(passport.session());

// parse application/x-www-form-urlencoded for web
app.use(bodyParser.urlencoded({extended: false}));
// parse application/json for mobile
app.use(bodyParser.json());

passport.use(new APIStrategy());

// Configure passport.js to use WebAppStrategy
passport.use(new WebAppStrategy());

let selfServiceManager = new SelfServiceManager();

// Configure passport.js with user serialization/deserialization. This is required
// for authenticated session persistence accross HTTP requests. See passportjs docs
// for additional information http://passportjs.org/docs
passport.serializeUser(function(user, cb) {
	cb(null, user);
});
passport.deserializeUser(function(obj, cb) {
	cb(null, obj);
});

app.get(ROP_LOGIN_PAGE_URL, function(req, res) {
	_render(req, res, loginEjs, {email: req.query && req.query.email}, req.query.language, req.flash('errorCode')[0]);
});

app.post(ROP_SUBMIT, function(req, res, next) {
	passport.authenticate(WebAppStrategy.STRATEGY_NAME, function (err, user, info) {
		if (err) {
			return next(err);
		}
		let language = req.query.language || 'es';
		let languageQuery = '?language=' + language;
		let emailInputQuery = '&email=' + req.body.username;
		if (!user) {
			req.flash('errorCode', info.code);
			return res.redirect(ROP_LOGIN_PAGE_URL + languageQuery + emailInputQuery);
		}
		req.logIn(user, function (err) {
			if (err) {
				return next(err);
			}
			return res.redirect(LANDING_PAGE_URL + languageQuery);
		});
	})(req, res, next);
});


// Callback to finish the authorization process. Will retrieve access and identity tokens/
// from App ID service and redirect to either (in below order)
// 1. the original URL of the request that triggered authentication, as persisted in HTTP session under WebAppStrategy.ORIGINAL_URL key.
// 2. successRedirect as specified in passport.authenticate(name, {successRedirect: "...."}) invocation
// 3. application root ("/")
app.get(CALLBACK_URL, passport.authenticate(WebAppStrategy.STRATEGY_NAME));

// Protected area. If current user is not authenticated - redirect to the login widget will be returned.
// In case user is authenticated - a page with current user information will be returned.
app.get(PROTECTED_ENDPOINT, passport.authenticate(WebAppStrategy.STRATEGY_NAME), function(req, res) {
	logger.debug(PROTECTED_ENDPOINT);
	let uuid = req.user.identities[0].id;
	selfServiceManager.getUserDetails(uuid).then(function (user) {
		let userDetails = {
			email: user.emails[0].value,
			firstName: user.name && user.name.givenName,
			lastName: user.name && user.name.familyName,
			phoneNumber: user.phoneNumbers && user.phoneNumbers[0].value
		};
		res.json(userDetails);
	}).catch(function (err) {
		logger.error(err);
		res.status(500).send('Something went wrong');
	});
});

app.get(CHANGE_PASSWORD_PAGE, passport.authenticate(WebAppStrategy.STRATEGY_NAME), function(req, res){
	logger.debug(CHANGE_PASSWORD_PAGE);
	_render(req, res, changePasswordEjs, {email: req.user.email}, req.query.language, req.flash('errorCode'));
});

app.post(CHANGE_PASSWORD_SUBMIT_MOBILE, passport.authenticate(APIStrategy.STRATEGY_NAME, {session: false}), function (req, res, next) {
	logger.debug(CHANGE_PASSWORD_SUBMIT_MOBILE);
	_changePassword(req, res, next, MOBILE_PLATFORM);
});

app.post(CHANGE_PASSWORD_SUBMIT, passport.authenticate(WebAppStrategy.STRATEGY_NAME), function (req, res, next) {
	logger.debug(CHANGE_PASSWORD_SUBMIT);
	_changePassword(req, res, next);
});

function _changePassword(req, res, next, platform) {
	let language = req.query.language || 'es';
	let languageQuery = '?language=' + language;
	let currentPassword = req.body['current_password'];
	let newPassword = req.body['new_password'];
	let confirmNewPassword = req.body['confirmed_new_password'];
	let email = req.user.email;
	
	if (!currentPassword || !newPassword || !confirmNewPassword) {
		logger.debug("Error: password can not be empty");
		if (platform === MOBILE_PLATFORM) {
			logger.debug("bad sign up input: password can not be empty");
			res.status(400).send("password can not be empty");
		} else {
			_render(req, res, signUpEjs, req.body, language, 'empty_password');
		}
	}
	if (!isSamePasswords(newPassword, confirmNewPassword)) {
		logger.debug("Error: password are not the same");
		if (platform === MOBILE_PLATFORM) {
			logger.debug("bad sign up input: password not the same" );
			res.status(400).send("passwords not the same");
		} else {
			req.flash('errorCode', 'passwords_mismatch');
			res.redirect(CHANGE_PASSWORD_PAGE + languageQuery);
		}
	} else {
		//placing the input for ROP login
		req.body.username = email;
		req.body.password = currentPassword;
		passport.authenticate(WebAppStrategy.STRATEGY_NAME, function (err, user, info) {
			if (err) {
				return next(err);
			}
			if (!user) {
				if (platform === MOBILE_PLATFORM) {
					return res.status(400).send("Incorrect current password");
				} else {
					req.flash('errorCode', 'incorrect_password');
					return res.redirect(CHANGE_PASSWORD_PAGE + languageQuery);
				}
			}
			req.logIn(user, function (err) {
				if (err) {
					return next(err);
				}
				selfServiceManager.setUserNewPassword(user.identities[0].id, newPassword, language).then(function (userInfo) {
					if (platform === MOBILE_PLATFORM) {
						res.status(200).send(userInfo);
					} else {
						let email = userInfo.emails[0].value;
						_render(req, res, passwordChangedSuccessEjs, {email: email}, language);
					}
				}).catch(function (err) {
					if (err.code) {
						logger.debug("error code:" + err.code + " ,bad change password input: " + err.message);
						if (platform === MOBILE_PLATFORM) {
							res.status(400).send(err.message);
						} else {
							req.flash('errorCode', err.code);
							res.redirect(CHANGE_PASSWORD_PAGE + languageQuery);
						}
					} else {
						logger.error(err);
						res.status(500).send('Something went wrong');
					}
				});
			});
		})(req, res, next);
	}
}

app.get(GET_USER_DETAILS, passport.authenticate(APIStrategy.STRATEGY_NAME, {session: false}), function(req, res) {
		logger.debug(CHANGE_DETAILS_PAGE);
		_getDetails(req, res, MOBILE_PLATFORM);
	}
);

app.get(CHANGE_DETAILS_PAGE, passport.authenticate(WebAppStrategy.STRATEGY_NAME), function(req, res){
	logger.debug(CHANGE_DETAILS_PAGE);
	_getDetails(req, res);
});

function _getDetails(req, res, platform) {
	let uuid = req.user.identities[0].id;
	selfServiceManager.getUserDetails(uuid).then(function (user) {
		let inputs = {
			email: user.emails[0].value,
			firstName: user.name && user.name.givenName,
			lastName: user.name && user.name.familyName,
			phoneNumber: user.phoneNumbers && user.phoneNumbers[0].value
		};
		if (platform === MOBILE_PLATFORM) {
			res.status(200).send(inputs);
		} else {
			_render(req, res, changeDetailsEjs, inputs, req.query.language);
		}
	}).catch(function (err) {
		logger.error(err);
		res.status(500).send('Something went wrong');
	});
}

app.post(CHANGE_DETAILS_SUBMIT_MOBILE, passport.authenticate(APIStrategy.STRATEGY_NAME, {session: false}), function (req, res) {
	logger.debug(CHANGE_DETAILS_SUBMIT_MOBILE);
	_changeDetails(req, res, MOBILE_PLATFORM);
});

app.post(CHANGE_DETAILS_SUBMIT, passport.authenticate(WebAppStrategy.STRATEGY_NAME), function(req, res) {
	logger.debug(CHANGE_DETAILS_SUBMIT);
	_changeDetails(req, res);
});

function _changeDetails(req, res, platform) {
	req.body.email = req.user.email;
	if (req.body.password) { //make sure password will not be changed
		delete req.body.password;
	}
	let userData = _generateUserScim(req.body);
	let language = req.query.language || 'es';
	let languageQuery = '?language=' + language;
	let uuid = req.user.identities[0].id;
	selfServiceManager.updateUserDetails(uuid, userData).then(function (userInfo) {
		if (platform === MOBILE_PLATFORM) {
			res.status(200).send(userInfo);
		} else {
			res.redirect(LANDING_PAGE_URL + languageQuery);
		}
	}).catch(function (err) {
		logger.error(err);
		res.status(500).send('Something went wrong');
	});
}

// Logout endpoint. Clears authentication information from session
app.get(LOGOUT_URL, function(req, res){
	WebAppStrategy.logout(req);
	res.redirect(LANDING_PAGE_URL);
});


function _generateUserScim(body) {
	let userScim = {};
	if (body.password) {
		userScim.password = body.password;
	}
	userScim.emails = [];
	userScim.emails[0] = {
		value: body.email,
		primary: true
	};
	if (body.phoneNumber) {
		userScim.phoneNumbers = [];
		userScim.phoneNumbers[0] = {
			value: body.phoneNumber
		};
	}
	if (body.firstName || body.lastName) {
		userScim.name = {};
		if (body.firstName) {
			userScim.name.givenName = body.firstName;
		}
		if (body.lastName) {
			userScim.name.familyName = body.lastName;
		}
	}
	if (body.language) {
		userScim.locale = body.language;
	}
	return userScim;
}

function isSamePasswords(password1, password2) {
	return password1 === password2;
}

function _render(req, res, ejs, inputs, language = 'es', errorCode) {
	let languageStrings = require("./public/translations/" + language);
	let errorMsg = errorCode ? (languageStrings.errors[errorCode] || errorCode): '';
	Object.assign(languageStrings, {message: errorMsg});
	Object.assign(languageStrings, inputs);
	
	//handling the case if running on mobile web, redirect with the custom scheme that will launch the handle activity
	if (ejs === signUpConfirmedEjs || ejs === resetPasswordFormEjs || ejs === resetPasswordExpiredEjs) {
		let userAgent = req.get('User-Agent');
		let isRunningOnMobileWeb = userAgent.indexOf('Mobile') > -1;
		let mobileRedirectUri;
		if (isRunningOnMobileWeb) {
			if (ejs === signUpConfirmedEjs) {
				mobileRedirectUri = encodeURI(mobileSignUpConfirmation);
			} else {
				mobileRedirectUri = encodeURI(mobileResetPasswordConfirmation);
			}
			mobileRedirectUri += encodeURIComponent('?uuid=' + inputs.uuid);
			mobileRedirectUri += encodeURIComponent('&language=' + language);
			if (inputs.code) {
				mobileRedirectUri += encodeURIComponent('&code=' + inputs.code);
			}
			if (inputs.errorStatusCode) {
				mobileRedirectUri += encodeURIComponent('&errorStatusCode=' + inputs.errorStatusCode);
				mobileRedirectUri += encodeURIComponent('&errorDescription=' + inputs.errorDescription);
			}
			logger.debug('mobileRedirectUri: ' + mobileRedirectUri);
		}
		languageStrings.mobileRedirectUri = mobileRedirectUri;
	}
	
	res.render(ejs, languageStrings);
}

app.get('/manifest.json', function (req, res) {
	res.sendFile(__dirname + '/manifest.json');
});

app.post(SIGN_UP_SUBMIT, function(req, res) {
	let userData = _generateUserScim(req.body);
	let language = req.query.language || 'es';
	let password = req.body.password;
	let rePassword  = req.body['confirmed_password'];
	let platform = req.params.platform;
	if (!password || !rePassword) {
		logger.debug("Error: password can not be empty");
		if (platform === MOBILE_PLATFORM) {
			logger.debug("bad sign up input: password can not be empty");
			res.status(400).send("password can not be empty");
		} else {
			_render(req, res, signUpEjs, req.body, language, 'empty_password');
		}
	} else if (!isSamePasswords(password, rePassword)) {
		logger.debug("Error: password are not the same");
		if (platform === MOBILE_PLATFORM) {
			logger.debug("bad sign up input: password not the same" );
			res.status(400).send("passwords not the same");
		} else {
			_render(req, res, signUpEjs, req.body, language, 'passwords_mismatch');
		}
	} else {
		selfServiceManager.signUp(userData, language).then(function (user) {
			logger.debug('user created successfully');
			if (platform === MOBILE_PLATFORM) {
				res.status(201).send(user);
			} else {
				_render(req, res, thanksForSignUpEjs,  {
					displayName: user.displayName ,
					email: user.emails[0].value,
					uuid: user.id
				}, language);
			}
		}).catch(function (err) {
			if (err && err.code) {
				logger.debug("error code:" + err.code + " ,bad sign up input: " + err.message);
				if (platform === MOBILE_PLATFORM) {
					res.status(400).send(err.message);
				} else {
					_render(req, res, signUpEjs, req.body, language, err.code);
				}
			} else {
				logger.error(err);
				res.status(500).send('Something went wrong');
			}
		});
	}
});

app.get(SIGN_UP_PAGE, function(req, res) {
	_render(req, res, signUpEjs, {firstName:'', lastName:'', email:req.query.email, phoneNumber:''}, req.query.language);
});

app.post(FORGOT_PASSWORD_SUBMIT, function(req, res) {
	let email = req.body && req.body.email;
	let language = req.query.language || 'es';
	let platform = req.params.platform;
	selfServiceManager.forgotPassword(email, language).then(function (user) {
		logger.debug('forgot password success');
		if (platform === MOBILE_PLATFORM) {
			res.status(202).send(user);
		} else {
			_render(req, res, resetPasswordSentEjs,  {
				displayName: user.displayName ,
				email: user.emails[0].value,
				uuid: user.id
			}, language);
		}
	}).catch(function (err) {
		res.status(err && err.statusCode || 500);
		if (err && err.statusCode >= 400 && err.statusCode < 500) {
			logger.debug("bad input for forgot password: " + err.message);
			if (platform !== MOBILE_PLATFORM) {
				if (err && err.statusCode === 404) {
					return _render(req, res, forgotPasswordEjs, req.body, language, USER_NOT_FOUND);
				}
			}
			res.send(err.message);
		} else {
			logger.error(err);
			res.send('Something went wrong');
		}
	});
});

app.get(FORGOT_PASSWORD_PAGE, function(req, res) {
	_render(req, res, forgotPasswordEjs, {message: req.flash('error'),  email: req.query.email}, req.query.language);
});

//resend notification endpoint
app.post(RESEND, function(req, res) {
	let uuid = req.body && req.body.uuid;
	let templateName = req.params && req.params.templateName;
	let language = req.query.language || 'es';
	let languageMessages = require("./public/translations/" + language).messages;
	selfServiceManager.resendNotification(uuid, templateName, language).then(function (success) {
		res.status(200).send(languageMessages.sent);
	}).catch(function (err) {
		if (err.statusCode === 409) {
			logger.debug(err.message);
			res.status(200).send(languageMessages.confirmed);
		} else {
			logger.error(err);
			res.status(200).send(languageMessages.tryLater);
		}
	});
});

app.get(ON_USER_VERIFIED, function (req, res) {
	let context = req.query.context;
	let language = req.query.language;
	selfServiceManager.getSignUpConfirmationResult(context).then(function (result) {
		let options = {
			errorStatusCode: '',
			errorDescription: '',
			uuid: result && result.uuid
		};
		if (result && result.success) {
			logger.debug('sign up result - success');
			_render(req, res, signUpConfirmedEjs, options, language);
		} else {
			if (result.error.code === 'GONE') {
				logger.debug('sign up result - failure: ' + result.error.description);
				options.errorStatusCode = 'GONE';
				options.errorDescription = result.error.description;
				_render(req, res, signUpConfirmedEjs, options, language);
			} else if (result.error.code === 'NOT_FOUND') {
				logger.debug('sign up result - failure: ' + result.error.description);
				options.errorStatusCode = 'NOT_FOUND';
				options.errorDescription = result.error.description;
				_render(req, res, signUpConfirmedEjs, options, language);
			} else {
				logger.error('unexpected sign up result ' + result);
				res.status(500);
				res.send('Something went wrong');
			}
		}
	}).catch(function (err) {
		logger.error(err);
		res.status(500);
		res.send('Something went wrong');
	});
});

app.get(ON_RESET_PASSWORD, function (req, res) {
	let context = req.query.context;
	let language = req.query.language;
	selfServiceManager.getForgotPasswordConfirmationResult(context).then(function (result) {
		let uuid = result && result.uuid;
		if (result && result.success) {
			//generate one time code and pass it to the reset password form,
			// here we do that in memory but it better to use DB like Redis to do that and store it for temporary time.
			let oneTimeCode = base64url.encode(crypto.randomBytes(24));
			resetPasswordCodesMap.set(oneTimeCode, {uuid: uuid});
			logger.debug('rendering ' + resetPasswordFormEjs);
			_render(req, res, resetPasswordFormEjs, {uuid: uuid, code: oneTimeCode}, language);
		} else {
			if (result.error.code === 'NOT_FOUND') {
				logger.debug('forgot password result - failure: ' + result.error.description);
				_render(req, res, resetPasswordExpiredEjs, {uuid: uuid, errorStatusCode: 'NOT_FOUND', errorDescription: result.error.description}, language);
			} else {
				logger.error('unexpected forgot password result ' + result);
				res.status(500);
				res.send('Something went wrong');
			}
		}
	}).catch(function (err) {
		logger.error(err);
		res.status(500);
		res.send('Something went wrong');
	});
});

app.post(RESET_PASSWORD_SUBMIT, function(req, res) {
	let uuid = req.body && req.body.uuid;
	let code = req.body && req.body.code;
	let newPassword = req.body['new_password'];
	let confirmNewPassword = req.body['confirmed_new_password'];
	let language = req.query.language || 'es';
	let platform = req.params.platform;
	
	if (!newPassword || !confirmNewPassword) {
		logger.debug("Error: password can not be empty");
		if (platform === MOBILE_PLATFORM) {
			logger.debug("bad sign up input: password can not be empty");
			res.status(400).send("password can not be empty");
		} else {
			_render(req, res, resetPasswordFormEjs, {}, language, 'empty_password');
		}
	} else if (!isSamePasswords(newPassword, confirmNewPassword)) {
		logger.debug('rendering reset password with error: password not the same');
		if (platform === MOBILE_PLATFORM) {
			logger.debug("bad sign up input: password not the same" );
			res.status(400).send("passwords not the same");
		} else {
			_render(req, res, resetPasswordFormEjs, {}, language, "passwords_mismatch");
		}
	} else {
		//validate the the passed code was generate by us
		let codeObject = resetPasswordCodesMap.get(code);
		if (codeObject) {
			if (uuid === codeObject.uuid) {
				//update the password and render the success page
				selfServiceManager.setUserNewPassword(uuid, newPassword, language).then(function (user) {
					logger.debug('successfully update user password');
					resetPasswordCodesMap.delete(code);
					if (platform === MOBILE_PLATFORM) {
						res.status(200).send(user);
					} else {
						let email = user.emails[0].value;
						_render(req, res, resetPasswordSuccessEjs, {email: email}, language);
					}
				}).catch(function (err) {
					if (err.statusCode === 400) {
						logger.debug("error code:" + err.statusCode + " ,bad reset password input: " + err.message);
						if (platform === MOBILE_PLATFORM) {
							res.status(400).send(err.statusCode);
						} else {
							_render(req, res, resetPasswordFormEjs, {}, language, err.message);
						}
					} else {
						logger.error('Error while trying to save user new password: ' + err.message);
						res.status(500).send('Something went wrong');
					}
				});
			} else {
				logger.error('The stored code object uuid does not match the passed uuid');
				res.status(500).send('Something went wrong');
			}
		} else {
			logger.error('The supplied code was not found in the resetPasswordCodesMap');
			res.status(500).send('Something went wrong');
		}
	}
});

// get the app environment from Cloud Foundry
var appEnv = cfenv.getAppEnv();
// start server on the specified port and binding host
app.listen(appEnv.port, '0.0.0.0', function() {
  // print a message when the server starts listening
  console.log("Cloud Land server starting on " + appEnv.url);
});
