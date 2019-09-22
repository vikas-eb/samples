const dal = require('../dal');
const Op = require('sequelize').Op;
const util = require('../util/');
const fetch = require('../util/fetch');
const db = require('../models').db;
const responseHelper = require('../util/response.helper');
const encryptionHelper = require('../util/encryption.helper');
const codes = require('../util/codes').codes;
const config = require('../config').config;
const listAttributes = require('../config').listAttributes;
const constants = require('../util/constants');
const messages = require('../util/messages').messages[constants.LANGUAGE];
const otp = require('./otp');


const _authenticate = async (email, password, requestSource) => {
	// find if email exists

	const where = {
		email,
		active: 1
	}
	const user = await dal.findOne(db.user, where, true);

	if (!user) {
		const error = util.generateWarning(messages.INVALID_CREDENTIALS);
		error.code = codes.EMAIL_DOESNOT_EXIST;

		throw error;
	}
	else {
		// validate password
		const passwordIsValid = encryptionHelper.validatePassword(password, user.password, user.passwordSalt);

		if (!passwordIsValid) {
			// couldn't authenticate the password
			const error = util.generateWarning(messages.INVALID_CREDENTIALS);
			error.code = codes.PASSWORD_INCORRECT;

			throw error;
		}
		else {

			// if user's email is not confirmed. Please throw an error
			if (user.emailConfirmed === 0)
				throw (util.generateWarning(messages.EMAIL_ID_NOT_CONFIRMED, codes.EMAIL_NOT_ACTIVATED));
			// password authenticated.

			if (((user && user.crmAccess !== true) || typeof user === 'undefined') && (requestSource === constants.SHOPPING.HOST_NAME.CRM_SHOPPING)) {
				// oopsie... we cannot proceed
				throw util.generateWarning(`You don't have access to CRM. If you are a vendor and need access to the system, please send email to helpdesk@thebigstack.com`, codes.NO_ACCESS_CRM);
			}

			_updateUserPropertiesOnFirstLogin(user, requestSource)
			return user;
		}
	}
};


/**
 *
 * @param {*} userOptions
 */

const _authenticate_social = async (userOptions, requestSource) => {
	const {
		token, email, facebookUserId, authType, source, referredByCode
	} = userOptions;
	let user = {};

	// authtype will confirm the source of call

	if (authType === 'facebook') {
		user = await _verifyFacebookTokenAndGetUserData(email, facebookUserId, token);
	} else {
		user = await _verifyGoogleTokenAndGetUserData(email, token);
	}

	// if we have come here, it means we have got the user object

	// let's try to find the user by email

	let _user = await _findUserWithEmail(email);


	/** two cases here
	 * 1. If the user is new, and the request is for CRM, cannot proceed. 
	 * 2. If the user is old, and the request is for CRM, and user doesn't have CRM access, just kick him out
	 */


	if (((_user && _user.crmAccess !== true) || typeof _user === 'undefined') && (requestSource === constants.SHOPPING.HOST_NAME.CRM_SHOPPING)) {
		// oopsie... we cannot proceed
		throw util.generateWarning(`You don't have access to CRM. If you are a vendor and need access to the system, please send email to helpdesk@thebigstack.com`, codes.NO_ACCESS_CRM);
	}


	if (_user) {
		// already exists. Let's not worry about it, and generate the token and send it back
		_updateUserPropertiesOnFirstLogin(_user, source);
	}
	else {
		// user doesn't exist. So let's create a user Automatically.

		const newUser = {
			email: user.email,
			profilePic: user.profilePic,
			active: 1, // active is true by default
			firstName: user.firstName,
			lastName: user.lastName,
			originPlatform: source,
			accessGroupId: process.env.DEFAULT_USER_GROUP,
			referralCode: util.generateRandomCode(6),
			referredByCode,
			customer: false,
			student: false,
			vendor: false,
			staker: false,
			player: false
		};

		switch (source) {
			case 'staking':
				newUser.staker = true;
				newUser.player = true;
				break;
			case 'shopping':
				newUser.customer = true;
				break;
			case 'coaching':
				newUser.student = true;
				break;
		}

		// let's update the rewards points, if available
		newUser.rewardPoints = 0;

		if (referredByCode) {
			if (otp._updateRewardPoints(referredByCode)) {
				newUser.rewardPoints = 100;
			}
		}

		// const specialRewards = util.getSpecialReward(newUser.email);

		// if (specialRewards > 0) {
		// 	newUser.rewardPoints = specialRewards;
		// }

		_user = await dal.saveData(db.user, newUser);
	}

	return _user;
};


const _updateUserPropertiesOnFirstLogin = (user, source) => {
	// update: 11 Sept 2019: if user is logging from a source first time, we need to make sure it has to be marked true
	const _user = JSON.parse(JSON.stringify(user));

	switch (source) {
		case constants.SHOPPING.HOST_NAME.STAKING:
			// to-do: let's sort it out for staking later on. How to handle player and staker thing
			break;
		case constants.SHOPPING.HOST_NAME.SHOPPING:
		case constants.SHOPPING.HOST_NAME.CRM_SHOPPING:
			if (!_user.customer) {
				// first time login in shopping
				const userData = {
					id: _user.id,
					customer: true
				};

				// let's not run a synced operation
				dal.saveData(db.user, userData);
			}
			break;
		case 'coaching':
			if (!_user.student) {
				// first time login in shopping
				const userData = {
					id: _user.id,
					student: true
				};

				// let's not run a synced operation as user doesn't care
				dal.saveData(db.user, userData);
			}
			break;
	}
};


const _deleteRecords = (ids, userId, res) => dal.deleteRecords(db.user, ids, userId, res);


const _deleteRecord = (id, userId, res) => _deleteRecords([id], userId, res);


const _findUserWithFacebookUserId = async (facebookUserId, isActive) => {
	const where = {};

	typeof isActive === 'undefined' ? '' : where.active = isActive;
	where.facebookId = facebookUserId;

	return await dal.findOne(db.user, where);
};


const _findUserWithMobile = async (phoneToSearch, isActive) => {
	const where = {};

	typeof isActive === 'undefined' ? '' : where.active = isActive;
	where.mobile = phoneToSearch;

	return await dal.findOne(db.user, where);
};


const _findUserWithEmail = async (emailToSearch, isActive) => {
	const where = {};

	typeof isActive === 'undefined' ? '' : where.active = isActive;
	where.email = emailToSearch;

	return await dal.findOne(db.user, where, true);
};


const _findUserWithId = async id => await dal.findById(db.user, id, true);


const _getUsersByEmail = async (nameToSearch) => {
	const users = await db.user.findAndCountAll({
		attributes: ['id', 'email', 'firstName', 'lastName'],
		where: {
			[Op.or]: {
				email: {
					[Op.like]: `%${nameToSearch}%`,
				},
				firstName: {
					[Op.like]: `%${nameToSearch}%`,
				},
				lastName: {
					[Op.like]: `%${nameToSearch}%`,
				},
			},
		},
		order: ['email', 'firstName', 'lastName'],
	});

	if (users && users.length > 0) {
		return users;
	}

	return [];
};


const _refreshToken = async (email, token) => {
	try {
		const _token = await db.token.findOne({
			where: {
				refreshToken: token,
				email,
			},
		});
		// if token is not null, then it is a valid token.

		if (typeof _token === 'undefined' || !_token) {
			// couldn't find token
			const error = util.generateWarning(messages.TOKEN_REFRESH_CANNOT_VALIDATE);
			error.code = codes.TOKEN_REFRESH_INCORRECT;

			throw error;
		} else {
			// token is good
			// now we need to generate a new token for the user

			// let's add some random key to generate a different pattern

			const authToken = util.jwtService.createJWT({
				email,
				userId: _token.UserId,
				randomBytes: encryptionHelper.randomBytes(5), // let's keep it short
				injectedKey: config.INJECTED_KEY,
			}, config.TOKEN_ALLOWED_FOR_HOW_LONG);

			// send it back
			return authToken;
		}
	} catch (error) {
		error.code = error.code ? error.code : codes.ERROR;
		throw error;
	}
};


const _register = async (_user, userId, access, oprRequest, requestSource) => {
	const invalidFields = util.missingRequiredFields('register', _user);

	if (invalidFields === '') {
		// the fields are valid

		// we need to verify:
		// 1. Phone number should not be in use
		// 2. Email should not be in use

		const _userWithNumber = await _findUserWithMobile(_user.mobile);

		/** if phone number is in use, then don't proceed at all */
		if (_userWithNumber && _userWithNumber.Mobile === _user.mobile) throw util.generateWarning('Phone number already in use', codes.PHONE_ALREADY_EXISTS);

		const _userWithEmail = await _findUserWithEmail(_user.email);

		/** if email is in use, then check if it is a google auth login or not
			 * and if it is google auth, we need to tell him, to login through google and then update the profile
			 * with more information.
			 *
			*/

		if (_userWithEmail && _userWithEmail.email === _user.email) {
			// user found.

			if (_userWithEmail.password === '' || typeof _userWithEmail.password === 'undefined') {
				// it is a social auth user
				throw util.generateWarning(messages.EMAIL_REGISTERED_SOCIAL, codes.EMAIL_ALREADY_EXISTS_SOCIAL_AUTH);
			}
			else if (_userWithEmail.emailConfirmed === false) {
				// let's try to save it again with new information
				_user.id = _userWithEmail.id;
			}
			else {
				// user's password is available. Don't proceed, the user already exists
				throw util.generateWarning(messages.EMAIL_ALREADY_EXISTS, codes.EMAIL_ALREADY_EXISTS);
			}
		}

		// ok, if it has come here, it is safe to register
		// let's save the user, and send the OTPs of user's email and phone

		// ok, let's move on with our work of registering

		switch (_user.source) {
			case 'staking':
				_user.subscribedToTBS = true;
				break;
			case 'shopping':
				_user.subscribedToShopping = true;
				break;
			case 'coaching':
				_user.subscribedToCoaching = true;
				break;
		}

		_user.originPlatform = _user.source || req.app;
		_user.active = true;
		_user.mobileConfirmed = false;
		_user.emailConfirmed = false;

		// hash the password for security
		const passwordSaltWrapper = encryptionHelper.hashPassword(_user.password);

		_user.password = passwordSaltWrapper.password;
		_user.passwordSalt = passwordSaltWrapper.salt;

		_user.referralCode = util.generateRandomCode(6);
		_user.accessGroupId = process.env.DEFAULT_USER_GROUP;

		let user = await dal.saveData(db.user, _user);

		if (_user.id) {
			user = _user;
		}
		// user is created successfully

		return user;
	}

	// invalid fields found. Return and throw an error
	throw util.generateWarning(`Invalid input provided. Fields - ${invalidFields} were not provided.`, codes.INPUT_INVALID);
};


/**
 *
 * @param {*} userId
 * @param {*} token
 *
 *
 * {
   "name": "Vikas Bhandari",
   "email": "vikasbhandari2\u0040gmail.com",
   "birthday": "10/17/1981",
   "location": {
      "id": "130646063637019",
      "name": "Noida, India"
   },
   "hometown": {
      "id": "106517799384578",
      "name": "New Delhi, India"
   },
   "id": "10156138825753196"
}
 *
 *
 */


const _verifyFacebookTokenAndGetUserData = async (email, facebookUserId, token) => {
	const result = await fetch.get(constants.FACEBOOK.AUTH_URL + token);
	const facebookWrapper = JSON.parse(result);

	// verify the email, userid, and token

	if (facebookWrapper.name && facebookWrapper.email && facebookWrapper.id) {
		if (facebookUserId === facebookWrapper.id && facebookWrapper.email === email) {
			const profilePic = constants.FACEBOOK.PICTURE_URL.replace('<%userid>', facebookUserId);
			const name = facebookWrapper.name;

			const names = name.split(' ');

			let firstName = '';
			let lastName = '';

			if (names.length === 1) {
				firstName = names[0];
			} else if (names.length === 2) {
				firstName = names[0];
				lastName = names[1];
			} else if (names.length > 2) {
				firstName = names[0];
				names.splice(0);

				lastName = names.join(' ');
			}

			return {
				firstName,
				lastName,
				profilePic,
				email,
			};
		}

		const error = util.generateWarning(messages.CANNOT_READ_TOKEN, codes.TOKEN_CANNOT_VERIFY);
		throw error;
	} else {
		const error = util.generateWarning(messages.CANNOT_READ_TOKEN, codes.TOKEN_MISSING_VALUES);
		throw error;
	}
};


/**
 *
 * @param {*} email
 * @param {*} token
 *
 * We need to make sure that the token derived is correct for google.
 *
 * Format of the Google API is:
 * {
  "iss": "accounts.google.com",
  "azp": "  283630251905-5v3sh5n6d7tvgke1jp5ogs3n3vt7t10h",
  "aud": "283630251905-5v3sh5n6d7tvgke1jp5ogs3n3vt7t10h.apps.googleusercontent.com",
  "sub": "116879369426382714287",
  "email": "vikasbhandari2@gmail.com",
  "email_verified": "true",
  "at_hash": "uaWXIg5hpByrUEfY4r9hDA",
  "name": "Vikas Bhandari",
  "picture": "https://lh6.googleusercontent.com/-ObjwQfQjpMs/AAAAAAAAAAI/AAAAAAAAAAA/IiIndLYaW7c/s96-c/photo.jpg",
  "given_name": "Vikas",
  "family_name": "Bhandari",
  "locale": "en",
  "iat": "1545042046",
  "exp": "1545045646",
  "jti": "1860f1caa1a85b9996ef2b7790db0c184972f26b",
  "alg": "RS256",
  "kid": "8d7bf7218832047dea3f74016fe45fd0d9d42a29",
  "typ": "JWT"
}
 *
 */
const _verifyGoogleTokenAndGetUserData = async (email, token) => {

	const result = await fetch.get(constants.GOOGLE.AUTH_URL + token);
	const googleWrapper = result;

	/**
	   * we should verify email and the app ID
	   */

	if (googleWrapper.email && googleWrapper.azp && googleWrapper.azp) {
		// match both the values

		if (googleWrapper.email.toLowerCase() === email.toLowerCase() && googleWrapper.azp === constants.GOOGLE.APP_ID) {
			// now  verify the google token

			const utcSeconds = googleWrapper.azp;
			const expiresAt = new Date(0); // The 0 there is the key, which sets the date to the epoch
			expiresAt.setUTCSeconds(utcSeconds);

			if (new Date() > new Date(expiresAt)) {
				// token is already expired
				const error = util.generateWarning('Google token has been expired.', codes.TOKEN_AUTH_EXPIRED);
				throw error;
			}

			// ok, this seems a valid request return user data
			return {
				firstName: googleWrapper.given_name,
				lastName: googleWrapper.family_name,
				profilePic: googleWrapper.picture,
				email,
			};
		}


		// invalid token

		const error = util.generateWarning(messages.CANNOT_AUTHENTICATE_TOKEN, codes.TOKEN_CANNOT_VERIFY);
		throw error;
	} else {
		const error = util.generateWarning(messages.CANNOT_READ_TOKEN, codes.TOKEN_MISSING_VALUES);
		throw error;
	}
};


const _generateHashCode = (email) => {
	const hashExpiresAt = util.dateAdd(new Date(), 'second', config.VERIFICATION_HASH_ALLOWED_FOR_HOW_LONG_SECONDS);
	const hashWrapper = { email, type: constants.ECRYPTIONTYPES.ACTIVATION_HASH, expiresAt: hashExpiresAt };
	return encryptionHelper.encryptText(JSON.stringify(hashWrapper));
};





/**
  * @api {post} /api/account/login Login
  * @apiName Login
  * @apiGroup Account

  *
  * @apiDescription Allows user to login a user through our login platform, or through the social auth. The logic is like below:
  *  If auth type is provided, then it picks up authenticate social, otherwise it goes through normal route
    <code>
  * if (req.body.authType === 'google' || req.body.authType === 'facebook') {
        user = await _authenticate_social(req.body);
    }
    else {
        user = await _authenticate(req.body.email, req.body.password);
    }
    </code>
  *
  * @apiParam {String} email
  * @apiParam {String} password
  * @apiParam {String} token The token generated after social auth
  * @apiParam {Integer} facebookUserId (only for facebook auth)
  * @apiParam {String} authType The authentication source - google/facebook
  * @apiParam {String} source the source, like shopping or staking
  * @apiParam {String} oprKey the mandatory opr key for all open requests to avoid phishing attacks
  * E
  *
  * @apiSuccess {Integer}   code            the custom code... 200 for success and Error codes for error.
  * @apiSuccess {Boolean}   success         true means the request worked as expected
  * @apiSuccess {String}   message          the message from the API , can be used to display as a info to user
  * @apiSuccess {Object}   data             the user object
  * @apiSuccess {String}  data.token
  * @apiSuccess {String}  data.refreshToken
  * @apiSuccess {DateTime}  data.expires
  * @apiSuccess {Object}  data.user          the user object
  * @apiSuccess {String}  data.user.id          Id of the user
  * @apiSuccess {String}  data.user.title
  * @apiSuccess {String}  data.user.firstName
  * @apiSuccess {String}  data.user.lastName
  * @apiSuccess {String}  data.user.middleName
  * @apiSuccess {String}  data.user.email
  * @apiSuccess {String}  data.user.mobile
  * @apiSuccess {Boolean}  data.user.subscribedToShopping
  * @apiSuccess {Boolean}  data.user.subscribedToCoaching
  * @apiSuccess {Boolean}  data.user.subscribedToTBS
  * @apiSuccess {Boolean}  data.user.emailConfirmed
  * @apiSuccess {Boolean}  data.user.mobileConfirmed

  *
  *
  * @apiError Error-Code-354 The associated info of the user cannot be verified
  * @apiError Error-Code-355 After decrypting token, we couldn't find the required fields
  * @apiError Error-Code-307 Email couldn't be found
  * @apiError Error-Code-331 Password incorrect
  *
*/


const authenticate = async (req, res) => {
	let user;

	const body = {
		...req.body,
		source: req.appName
	};

	try {
		if (req.body.authType === 'google' || req.body.authType === 'facebook') {
			// required fields check
			if (util.missingRequiredFields('login_social', req.body, res) === '') user = await _authenticate_social(body, req.tbsHostName);
		}
		else {
			// required fields check
			if (util.missingRequiredFields('login', req.body, res) === '') user = await _authenticate(req.body.email, req.body.password, req.tbsHostName);
		}

		// authenticated successfully. Now let's store a refresh token. First, let's create a token
		const refreshToken = encryptionHelper.randomBytes(40, 'base64');

		const dataToSave = {
			refreshToken,
			email: user.email,
			userId: user.id,
		};

		const vendor = user.vendor;

		await db.token.create(dataToSave);

		// token saved successfully. Now we will just return back the data
		// let's create a JWT Token

		const tokenExpiresAt = util.dateAdd(new Date(), 'hour', 2);

		const authToken = util.jwtService.createJWT({
			email: user.email,
			userId: user.id,
			firstName: user.firstName,
			lastName: user.lastName,
			injectedKey: config.INJECTED_KEY,
			appName: req.appName,
			vendorId: user.vendor ? user.vendor.id : 'not-a-vendor'
		}, config.TOKEN_ALLOWED_FOR_HOW_LONG);

		const authPacket = {
			token: authToken,
			refreshToken,
			exipres: tokenExpiresAt,
			user: {
				id: user.id,
				firstName: user.firstName,
				lastName: user.lastName,
				middleName: user.middleName,
				title: user.title,
				email: user.email,
				mobile: user.mobile,
				subscribedToCoaching: user.subscribedToCoaching,
				subscribedToShopping: user.subscribedToShopping,
				subscribedToTBS: user.subscribedToTBS,
				mobileConfirmed: user.mobileConfirmed,
				emailConfirmed: user.emailConfirmed,
				addresses: user.addresses,
				referralCode: user.referralCode,
				rewardPoints: user.rewardPoints ? user.rewardPoints : 0,
				userType: user.userType,
				socialAuth: user.password === null
			},
		};

		responseHelper.success(res, 200, authPacket, messages.LOGGED_IN_SUCCESSFULLY);
	}
	catch (error) {
		responseHelper.error(res, error, error.code ? error.code : codes.ERROR, 'Authentication Error');
	}
};


/**
 *
 * @param {*} req
 * @param {*} res
 */

/**
 * @api {post} /api/account/register Register user
 * @apiName Register
 * @apiGroup Account

 *
 * @apiDescription Registers a new user.
 *
 * @apiParam {String} title Title of the registering person
 * @apiParam {String} firstName First Name
 * @apiParam {String} lastName Last name
 * @apiParam {String} email The unique email address to be used for auth later on
 * @apiParam {String} password
 * @apiParam {String} address1
 * @apiParam {String} address2
 * @apiParam {String} city
 * @apiParam {String} state
 * @apiParam {String} zip
 * @apiParam {String} country
 * @apiParam {String} mobile
 * @apiParam {String} phone
 * @apiParam {String} gender
 * @apiParam {String} profilePic
 * @apiParam {String} source Source like Staking/Shopping/
 * @apiParam {Date} dob Date Of birth
 * @apiParam {Date} doj Date of Joining the platform
 *
 * @apiSuccess {Integer}   code            the custom code 200 for success.
 * @apiSuccess {Boolean}   success         true means the request worked as expected
 * @apiSuccess {String}   message          the message from the API , can be used to display as a info to user
 * @apiSuccess {Object}   data             the user object
 * @apiSuccess {Integer}  data.ed          Id of the user
 * @apiSuccess {Integer}  data.email       Email of the user
 *
 * @apiError Error-Code-391 Required fields not present
 * @apiError Error-Code-309 Email already exists with the social auth
 * @apiError Error-Code-305 Email already exists
 * @apiError Error-Code-305-1 Phone already exists
 * @apiError Error-Code-381 Couldn't send otp
 *
*/

const register = async (req, res) => {
	try {
		const user = await _register(req.body, req.user ? req.user.id : -1, req.access, req.oprRequest);

		// send OTP to user on their mobile and email
		// send res as null coz we don't wanna send the response yet
		await otp._generateAndSendOTP(null, user.id, user.mobile, 'mobile', undefined, undefined, user.firstName);

		await otp._generateAndSendOTP(null, user.id, user.email, 'email', undefined, undefined, user.firstName);

		// coming here means that the user has been registered successfully.
		responseHelper.success(res, 200, { id: user.id, email: user.email }, messages.REGISTERED_SUCCESSFULLY);

		return user;
	} catch (error) {
		responseHelper.error(res, error, error.code ? error.code : 502, 'Registering user');
	}
};


/**

 * @api {post} /api/account/forgotPassword Forgot Password
 * @apiName forgotPassword
 * @apiGroup Account

 * @apiDescription It sends the OTP to registered mobile/email. Please note that first it tries to find the user with mobile, and then by email. If we are able to find a user with mobile, we will then use the found user's mobile and email to send OTP.


 * @apiParam {String} mobile Either email or phone number is required to retrieve password. Phone is given preference over Email if both supplied
 * @apiParam {String} email Either email or phone number is required to retrieve password. Phone is given preference over Email if both supplied

 * @apiSuccess {Integer}   code  The code of the response/error. 200 means the request is successful
 * @apiSuccess {String}   message  The message from the API. It can be used for displaying it to the user.
 * @apiSuccess {Object}   data  The data packet, where all the requests will be abstracted
 * @apiSuccess {String}   data.userId  The Id of the user found in the system.

 * @apiError Error-Code-391 The user is not found with either email or mobile.
 * @apiError Error-Code-309 The user is registered through Social Auth
 * @apiError Error-Code-381 Error in sending OTP. <code>message<code> will contain description
 * @apiError Error-Code-308 The error in sending email. Check <code>message<code> for further information
 */

const forgotPassword = async (req, res) => {
	try {
		// check if user id exists or not
		let user;

		if (req.body.mobile) {
			user = await _findUserWithMobile(req.body.mobile);
		} else if (req.body.email) {
			user = await _findUserWithEmail(req.body.email);
		} else {
			responseHelper.error(res, new Error(messages.PROVIDE_EMAIL_MOBILE), codes.INPUT_INVALID, 'forgot password');
		}


		if (user) {
			// if the user is google/facebook user, tell him to login from that login
			if (!user.password || user.password === '' || typeof user.password === 'undefined') {
				// it is a social auth user
				throw util.generateWarning(messages.EMAIL_REGISTERED_SOCIAL, codes.EMAIL_ALREADY_EXISTS_SOCIAL_AUTH);
			}

			// if not, let's send the OTP

			const code = util.generateRandomCode(config.OTP_LENGTH);

			if (user.email) {
				await otp._generateAndSendOTP(undefined, user.id, user.email, 'email', 'password', code);
			}

			if (user.mobile) {
				await otp._generateAndSendOTP(undefined, user.id, user.mobile, 'mobile', 'password', code);
			}

			// if it comes here, it means the otp has been delivered. Otherwise the error will come and the control
			// will not come here

			responseHelper.success(res, 200, { userId: user.id }, messages.OTP_SENT_EMAIL_MOBILE);
		}
		else {
			const error = util.generateWarning(messages.USER_ID_NOT_FOUND, codes.ID_NOT_FOUND);
			throw error;
		}
	}
	catch (error) {
		responseHelper.error(res, error, error.code ? error.code : codes.ERROR, 'resetting password');
	}
};


/**

 * @api {post} /api/account/resetPassword Reset password
 * @apiName ResetPassword
 * @apiGroup Account

 * @apiDescription For refreshing password, we will need to use password token. While verifying the otp, you will be sent a password token in response. You will need to send this in the body so we can authenticate the request


 * @apiParam {String} userId
 * @apiParam {String} passwordToken
 * @apiParam {String} password
 * @apiParam {String} confirmPassword

 * @apiSuccess {Integer}   code  The code of the response/error. 200 means the request is successful and password is updated
 * @apiSuccess {String}   message  The message from the API. It can be used for displaying it to the user.
 * @apiSuccess {Object}   data  Not Used

 * @apiError Error-Code-301 The user is not found with the Id. Id may be incorrect.
 * @apiError Error-Code-354 The password token cannot be verified after decrypting. It will mostly mean that the user id you sent in request is different from the user id for which this token was originally issued to.
 * @apiError Error-Code-352 Password token expired
 * @apiError Error-Code-353 Token is corrupted or messed up
 * @apiError Error-Code-355 The token didn't have expected values after decrypting. It seems it was tampered with
 * @apiError Error-Code-333 Password not provided
 * @apiError Error-Code-334 Password and confirm password do not match
 * @apiError Error-Code-309 The user is registered through Social Auth so cannot update the password.
 */

const resetPassword = async (req, res) => {
	try {
		// verify the token

		const { password, confirmPassword } = req.body;

		const tokenObject = JSON.parse(encryptionHelper.decryptText(req.body.passwordToken));

		if (tokenObject && tokenObject.userId && tokenObject.key && tokenObject.expiresAt) {
			if (tokenObject.userId !== req.body.userId) {
				// invalid token
				throw util.generateWarning(messages.INVALID_PASSWORD_TOKEN, codes.TOKEN_CANNOT_VERIFY);
			}

			// check if it has not been expired

			if (new Date() > new Date(tokenObject.expiresAt)) {
				// expired
				throw util.generateWarning(messages.EXPIRED_PASSWORD_TOKEN, codes.TOKEN_AUTH_EXPIRED);
			}

			if (tokenObject.key !== config.INJECTED_KEY) {
				// expired
				throw util.generateWarning(messages.INVALID_PASSWORD_TOKEN, codes.TOKEN_AUTH_CORRUPTED);
			}

			// token ok
		} else {
			throw util.generateWarning(messages.INVALID_PASSWORD_TOKEN, codes.TOKEN_MISSING_VALUES);
		}

		if (!password || typeof password === 'undefined') {
			throw util.generateWarning(messages.INVALID_PASSWORD, codes.PASSWORD_NOT_PROVIDED);
		}

		if (password !== confirmPassword) {
			throw util.generateWarning(messages.PASSWORD_CONFIRM_NO_MATCH, codes.PASSWORD_NOT_MATCHED);
		}

		// check if user id exists or not
		const user = await _findUserWithId(req.body.userId);

		if (user) {
			// if the user is google/facebook user, tell him to login from that login
			if (user.password === '' || typeof user.password === 'undefined') {
				// it is a social auth user
				throw util.generateWarning(messages.EMAIL_REGISTERED_SOCIAL, codes.EMAIL_ALREADY_EXISTS_SOCIAL_AUTH);
			}

			// save the user with new password

			const passwordSaltWrapper = encryptionHelper.hashPassword(password);

			const userData = {
				id: user.id,
				password: passwordSaltWrapper.password,
				passwordSalt: passwordSaltWrapper.salt,
			};

			await dal.saveData(db.user, userData);

			responseHelper.success(res, 200, {}, messages.PASSWORD_UPDATED);
		} else {
			const error = util.generateWarning(messages.USER_ID_NOT_FOUND, codes.ID_NOT_FOUND);
			throw error;
		}
	} catch (error) {
		responseHelper.error(res, error, error.code ? error.code : codes.ERROR, 'resetting password');
	}
};


/**

 * @api {post} /api/account/refreshToken Refresh token
 * @apiName refreshToken
 * @apiGroup Account

 * @apiDescription If the token is expired, you will need to submit a request with the refresh token, and it will return a new auth token

 * @apiParam {String} email
 * @apiParam {String} refreshToken

 * @apiSuccess {Integer}   code  The code of the response/error
 * @apiSuccess {String}   message  The message from the API. It can be used for displaying it to the user.
 * @apiSuccess {Object}   data  The data packet, where all the requests will be abstracted
 * @apiSuccess {String}   data.token  The token to send requests again.

 * @apiError Error-Code-351 The refresh token provided cannot be validated.
 */

const refreshToken = (req, res) => new Promise((resolve, reject) => {
	_refreshToken(req.body.email, req.body.refreshToken).then((token) => {
		responseHelper.success(res, 200, { token }, messages.TOKEN_REFRESH_SUCCESSFULL);
		resolve(token);
	}).catch((error) => {
		responseHelper.error(res, error, error.code ? error.code : 502, 'Refresh Token');
		reject(error);
	});
});


/**

 * @api {post} /api/account/tokenIsValid Validate token
 * @apiName TokenIsValid
 * @apiGroup Account

 * @apiDescription Validates the auth token


 * @apiParam {String} token

 * @apiSuccess {Integer}   code  The code of the response/error. 200 means the Token is valid.
 * @apiSuccess {String}   message  The message from the API. It can be used for displaying it to the user.

 * @apiError Error-Code-352 Auth token is expired
 * @apiError Error-Code-353 Auth token is corrupted/incorrect
 */


const tokenIsValid = (req, res) => {
	const decoded = util.tokenIsValid(req.body.token);

	if (decoded.isError) {
		responseHelper.error(res, decoded.error, decoded.error.code, 'Token validation');
	} else {
		responseHelper.success(res, 200, {}, messages.TOKEN_VALID);
	}
};


/**
 *
 * @param {*} req
 * @param {*} res
 *
 * For normal Auth
 * {
 *      email: 'vikasbhandari2@gmail.com',
 *      password: 'password'
 * }
 *
 * for social Auth
 * {
 *      email: 'vikasbhandari2@gmail.com',
 *      firstName: '',
 *      lastName: '',
 *      facebookUserId: '' // only for facebook login
 *      token: '',
 *      authType: 'google' / 'facebook' one of it,
 *      source: 'Shopping'
 *
 * }
 */


const saveUser = async (req, res) => {
	try {
		const user = req.body;

		const sendOTP = {
			mobile: false,
			email: false,
		};


		// this is an edit request
		// when we save a different mobile, or email, we need to make sure we send the OTP.

		// let's delete the records which are not supposed to be coming from front end

		if (user.subscribedToCoaching) delete user.subscribedToCoaching;
		if (user.subscribedToShopping) delete user.subscribedToShopping;
		if (user.subscribedToTBS) delete user.subscribedToTBS;
		if (user.mobileConfirmed) delete user.mobileConfirmed;
		if (user.emailConfirmed) delete user.emailConfirmed;

		// get the record with ID
		const _user = await _findUserWithId(user.id);

		/** there will be few instances of saving a user
		 * 1. Saving by user himself
		 * 2. Saving by adming through CRM
		 * 3. Saving by vendor management, through CRM
		 */

		// this is a safe guarded request, so the req will always have a user id

		if (_user && _user.id === req.user.id) {
			// this request was raised by the user himself

			// check if the mobile changed
			if (_user.mobile !== user.mobile && user.mobile) {
				// ok, that is a problem , let's send the OTP
				sendOTP.mobile = true;
				user.mobileConfirmed = false;
			} else {

			}

			// even though I am using Email as user name, but we are not yet sure about the flow yet
			// so let's just check if email changed

			if (_user.email !== user.email && user.email) {
				// ok, that is a problem , let's send the OTP
				sendOTP.email = true;
				user.emailConfirmed = false;
			} else {

			}
		}
		else if (typeof user.id !== 'undefined') {
			// it means the request is from admin, who is trying to save a user
		}
		else {
			// there is no id, now it can be two situation, 1. admin saving user, 2. admin saving a new vendor

			// let's try to find if the user exists in the system

			const _userWithEmail = await dal.findOne(db.user, {
				email: user.email
			});

			if (_userWithEmail) {
				// user exists, let's raise an error
				return responseHelper.success(res, codes.EMAIL_ALREADY_EXISTS, _userWithEmail.id, messages.EMAIL_ALREADY_EXISTS)
			}
		}

		// save user

		const userSaveResult = await dal.saveData(db.user, user, undefined, req.user ? req.user.id : -1);

		// user saved, now send the OTP, if required
		if (sendOTP.email) {
			// send otp
			await otp._generateAndSendOTP(undefined, user.id, user.email, 'email');
		}

		if (sendOTP.mobile) {
			// send otp
			await otp._generateAndSendOTP(undefined, user.id, user.mobile, 'mobile');
		}

		// no error means the OTP were delivered successfully
		// let's send the response back

		responseHelper.success(res, codes.SUCCESS, {}, messages.USER_SAVED, userSaveResult.id, 1);

	} catch (error) {
		// error found
		responseHelper.error(res, error, error.code, 'Updating User');
	}
};


const changePassword = async (req, res) => {
	try {
		/**
		 * for changing password, we need to make sure that the password is matched first.
		 */

		// let's find the user first
		const user = await _findUserWithId(req.user.id);

		if (!user) {
			throw util.generateWarning(messages.USER_ID_NOT_FOUND, codes.ID_NOT_FOUND);
		}

		// user found, let's try to compare the password
		const passwordIsValid = encryptionHelper.validatePassword(req.body.password, user.password, user.passwordSalt);

		if (!passwordIsValid) {
			throw util.generateWarning(messages.INVALID_PASSWORD, codes.PASSWORD_INCORRECT);
		}

		// password matched. Now make sure the new passwords match

		if (req.body.newPassword !== req.body.confirmPassword) {
			throw util.generateWarning(messages.PASSWORD_CONFIRM_NO_MATCH, codes.PASSWORD_NOT_MATCHED);
		}

		// hash the password for security
		const passwordSaltWrapper = encryptionHelper.hashPassword(req.body.newPassword);


		// let's change the password. 

		const userData = {
			id: user.id,
			password: passwordSaltWrapper.password,
			passwordSalt: passwordSaltWrapper.salt
		};

		await dal.saveData(db.user, userData);

		responseHelper.success(res, 200, {}, 'Password updated successfully');
	} catch (error) {
		responseHelper.error(res, error, codes.ERROR, 'get user name');
	}
};

/**

 * @api {put} /api/user
 * @apiName /api/user(put)
 * @apiGroup user

 * @apiDescription


 * @apiParam {Integer} rowsToReturn
 * @apiParam {Integer} pageIndex

 * @apiSuccess {Integer}   code  The code of the response/error. 200 means the request is successful and save is successful
 * @apiSuccess {String}   message  The message from the API. It can be used for displaying it to the user.

 * @apiError Error-Code-403 Unauthorized.
 * @apiError Error-Code-375 URL Malformed, API tries to split the url by '/' and if it doesn't find the required format, ex, '/api/user/' then it is considered as malformed
 * @apiError Error-Code-352 Auth token is expired
 * @apiError Error-Code-353 Auth token is corrupted/incorrect
 * @apiError Error-Code-355 The token didn't have expected values after decrypting. It seems it was tampered with
 * @apiError Error-Code-301 The user is not found with the Id. Id may be incorrect.
 * @apiError Error-Code-381 Error in sending OTP. <code>message<code> will contain description. OTP will be sent if mobile or email is changed
 * @apiError Error-Code-308 The error in sending email. Check <code>message<code> for further information. OTP will be sent if mobile or email is changed
 */

const deleteRecord = async (req, res) => {
	try {
		const user = await _findUserWithId(req.params.id);

		if (!user) {
			// we couldn't find the user. Raise an error
			const error = util.generateWarning(messages.USER_ID_NOT_FOUND, codes.ID_NOT_FOUND);
			throw error;
		}

		await dal.deleteRecord(db.user, user.id, req.user.userId, res);
	} catch (error) {
		responseHelper.error(res, error, error.code ? error.code : codes.ERROR, 'deleting user');
	}
};


/**

 * @api {get} /api/user/getUsersByEventId/:eventId Get users for an Events
 * @apiName Get users for an Event
 * @apiGroup User

 * @apiDescription Gets the user for an event

 * @apiParam {String} eventId

 * @apiSuccess {Integer}   code  The code of the response/error. 200 means the request is successful and event was deleted successfully
 * @apiSuccess {String}   message  The message from the API. It can be used for displaying it to the user.
 * @apiSuccess {Object[]}   data  list of users
 * @apiSuccess {String} data.id
 * @apiSuccess {String} data.firstName
 * @apiSuccess {String} data.lastName
 * @apiSuccess {String} data.email
 * @apiSuccess {String} data.mobile
 * @apiSuccess {String} data.emailConfirmed
 * @apiSuccess {String} data.mobileConfirmed
 * @apiSuccess {String} data.eventSubscriptionId
 * @apiSuccess {Integer} data.bulletsNeeded
 * @apiSuccess {Double} data.buyInAmount
 * @apiSuccess {String} data.eventName

 * @apiError Error-Code-301 Cannot find the event with the ID.
 * @apiError Error-Code-403 Unauthorized.
 * @apiError Error-Code-375 URL Malformed, API tries to split the url by '/' and if it doesn't find the required format, ex, '/api/user/' then it is considered as malformed
 * @apiError Error-Code-352 Auth token is expired
 * @apiError Error-Code-353 Auth token is corrupted/incorrect
 * @apiError Error-Code-355 The token didn't have expected values after decrypting. It seems it was tampered with
 */


const getUsersByEventId = async (req, res) => {
	try {
		const eventId = req.params.eventId;
		const event = await dal.findById(db.event, eventId);

		if (!event) {
			// ok, no event found
			throw util.generateWarning('Cannot find Event with the passed Id', codes.ID_NOT_FOUND);
		}

		db.sequelize.query('CALL Get_Users_By_Event_Id(:eventId);', {
			replacements: { eventId },
		}).then((response) => {
			responseHelper.success(res, 200, response, '');
		}).error((err) => {
			throw err;
		});
	} catch (error) {
		responseHelper.error(res, error, error.code ? error.code : codes.ERROR, 'Get Users by Event');
	}
};


const getUserById = async (req, res) => {
	try {
		const user = await _findUserWithId(req.params.id);
		if (user) {
			responseHelper.success(res, codes.SUCCESS, user);
		} else {
			const error = util.generateWarning(messages.USER_ID_NOT_FOUND, codes.ID_NOT_FOUND);
			throw error;
		}
	} catch (error) {
		responseHelper.error(res, error, error.code ? error.code : codes.ERROR, 'get user by id');
	}
};


/**

 * @api {get} /api/user gets the user list
 * @apiName /api/user(get)
 * @apiGroup user

 * @apiDescription Gets the users list, and allows pagination data


 * @apiParam {Integer} rowsToReturn
 * @apiParam {Integer} pageIndex

 * @apiSuccess {Integer}   code  The code of the response/error. 200 means the request is successful and password is updated
 * @apiSuccess {String}   message  Empty, no significance in this method
 * @apiSuccess {Object[]}   data
 * @apiSuccess {String}   data.id  User Id
 * @apiSuccess {String}   data.firstName
 * @apiSuccess {String}   data.lastName
 * @apiSuccess {String}   data.title
 * @apiSuccess {String}   data.gender
 * @apiSuccess {Date}   data.dob
 * @apiSuccess {Date}   data.doj
 * @apiSuccess {String}   data.address1
 * @apiSuccess {String}   data.city
 * @apiSuccess {String}   data.state
 * @apiSuccess {String}   data.mobile
 * @apiSuccess {String}   data.phone
 * @apiSuccess {String}   data.email
 * @apiSuccess {Boolean}   data.subscribedToTBS
 * @apiSuccess {Boolean}   data.subscribedToCoaching
 * @apiSuccess {Boolean}   data.subscribedToShopping
 * @apiSuccess {Integer}   count  Total number of users. For example, we may be returning 50 users in a request, this count will be showing the actual number of users in the DB. It will be used for your pagination

 * @apiError Error-Code-403 Unauthorized.
 * @apiError Error-Code-375 URL Malformed, API tries to split the url by '/' and if it doesn't find the required format, ex, '/api/user/' then it is considered as malformed
 * @apiError Error-Code-352 Auth token is expired
 * @apiError Error-Code-353 Auth token is corrupted/incorrect
 * @apiError Error-Code-355 The token didn't have expected values after decrypting. It seems it was tampered with
 */

const getUsers = async (req, res) => {
	try {
		// const order_by = req.query.sort ? req.query.sort.split(',') : [];
		// const order_by_direction = req.query.sort ? req.query.sort.split(',') : 'asc';

		// const sortingArray = [];

		// order_by.forEach(sortColumn => {
		//     sortingArray.push([sortColumn, order_by_direction]);
		// });

		const rowsToReturn = (req.query && req.query.rows) ? req.query.rows : undefined;
		const pageIndex = (req.query && req.query.pageIndex) ? req.query.pageIndex : undefined;

		let where = [];
		if (req.query.where) {
			where = JSON.parse(req.query.where.split('%22').join('\''));

			if (!Array.isArray(where)) {
				where = [];
			}
		}


		const users = await dal.getList(db.user, where, [], false, rowsToReturn, pageIndex,
			undefined, undefined, undefined, listAttributes.user);

		if (users && users.length > 0) {
			responseHelper.success(res, 200, users, '', -1, users.length);
		} else {
			responseHelper.success(res, 200, [], '', -1, 0);
		}
	} catch (error) {
		responseHelper.error(res, error, error.code ? error.code : codes.ERROR, 'get user list');
	}
};


/**
 * 
 * @param {*} req 
 * @param {*} res 
 * 
 * We need to deduct the rewards points for the users
 */
const rewardsUsed = async (req, res) => {
	const rewardUsed = req.params.rewardPoints;

	try {
		console.log('haiya....');
		const user = await dal.findById(db.user, req.user.id);

		if (!user) {
			throw util.generateWarning(messages.USER_ID_NOT_FOUND, codes.ID_NOT_FOUND);
		}

		// let's check if rewards are valid

		if (rewardUsed > (user.rewardPoints || 0)) {
			throw util.generateWarning('Insufficient reward points. You can only claim ' + (user.rewardPoints || 0) + ' points', codes.REWARD_POINTS);
		}

		const userToSave = {
			id: req.user.id,
			rewardPoints: user.rewardPoints - parseInt(rewardUsed)
		};

		console.log('nice...', userToSave);

		await dal.saveData(db.user, userToSave, res, req.user.id);
	} catch (error) {
		responseHelper.error(res, error, codes.ERROR, 'rewards redemption');
	}


};

/**
 * 
 * @param {*} req 
 * @param {*} res 
 * 
 * We need to add the rewards points for the users if the order didn't go through
 */
const addRewards = async (req, res) => {
	const rewardUsed = req.params.rewardPoints;

	try {
		const user = await dal.findById(db.user, req.user.id);

		if (!user) {
			throw util.generateWarning(messages.USER_ID_NOT_FOUND, codes.ID_NOT_FOUND);
		}

		const userToSave = {
			id: req.user.id,
			rewardPoints: (user.rewardPoints || 0) + parseInt(rewardUsed)
		};

		await dal.saveData(db.user, userToSave, res, req.user.id);
	} catch (error) {
		responseHelper.error(res, error, codes.ERROR, 'rewards added');
	}
};


const searchUsers = async (req, res) => {
	try {
		const users = await _getUsersByEmail(req.body.textToSearch);
		responseHelper.success(res, 200, users, '', -1, users.length);
	} catch (error) {
		responseHelper.error(res, error, codes.ERROR, 'get user name');
	}
};

/** testing URLs => to be removed later on */
module.exports._register = _register;
module.exports._deleteRecord = _deleteRecord;
module.exports._deleteRecords = _deleteRecords;
module.exports._authenticate = _authenticate;
module.exports._refreshToken = _refreshToken;
module.exports._findUserWithMobile = _findUserWithMobile;
module.exports._findUserWithEmail = _findUserWithEmail;
module.exports._findUserWithId = _findUserWithId;
module.exports._findUserWithFacebookUserId = _findUserWithFacebookUserId;
module.exports._verifyGoogleTokenAndGetUserData = _verifyGoogleTokenAndGetUserData;
module.exports._verifyFacebookTokenAndGetUserData = _verifyFacebookTokenAndGetUserData;


/** api URLs */
module.exports.changePassword = changePassword;
module.exports.deleteRecord = deleteRecord;
module.exports.forgotPassword = forgotPassword;
module.exports.authenticate = authenticate;
module.exports.refreshToken = refreshToken;
module.exports.tokenIsValid = tokenIsValid;
module.exports.getUsers = getUsers;
module.exports.getUsersByEventId = getUsersByEventId;
module.exports.getUserById = getUserById;
module.exports.register = register;
module.exports.resetPassword = resetPassword;
module.exports.saveUser = saveUser;
module.exports.searchUsers = searchUsers;
module.exports.rewardsUsed = rewardsUsed;
module.exports.addRewards = addRewards;
