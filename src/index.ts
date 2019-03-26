import { runStrategy } from 'passport-strategy-runner';
import { Strategy } from 'passport-strategy';
import * as passport from 'passport';
import {
    AuthenticationSuccess,
    ExegesisPluginContext,
    AuthenticationResult,
    Callback,
    Authenticator,
    AuthenticationFailure,
    AuthenticatorInfo
} from 'exegesis';

export type PassportToExegesisResult =
    (Pick<AuthenticationSuccess, 'user' | 'roles' | 'scopes'>) &
    {[prop: string]: any};

export interface PassportUserToExegesisUserFn {
    (
        user: any,
        pluginContext: ExegesisPluginContext
    ) : PassportToExegesisResult;
}

export interface IsPresentFn {
    (
        pluginContext: ExegesisPluginContext,
        info: AuthenticatorInfo
    ) : boolean;
}

export interface Options {
    convert?: PassportUserToExegesisUserFn;
    isPresent?: IsPresentFn;
    passportOptions?: any;
}

function isPassportAuthenticator(obj: any) : obj is passport.Authenticator {
    return obj.use && obj.authenticate && obj.initialize && obj.session;
}

function isString(obj: any) : obj is string {
    return typeof(obj) === 'string';
}

/* istanbul ignore next */
function assertNever(x: never): never {
    throw new Error("Unexpected object: " + JSON.stringify(x));
}

function defaultConverter(user: any) {
    return {
        user: user,
        roles: user.roles,
        scopes: user.scopes
    };
}

function defaultIsPresent(context: ExegesisPluginContext, info: AuthenticatorInfo) {
    let answer = true; // Assume worst case.

    if(info.name && info.in === 'header' && !(info.name.toLowerCase() in context.req.headers)) {
        answer = false;
    } else if(info.name && info.in === 'query' && !context.req.url!.includes(info.name)) {
        answer = false;
    } else if(info.scheme) {
        const authorization = context.req.headers['authorization'];
        const scheme = info.scheme.toLowerCase();
        if(authorization === null || authorization === undefined) {
            answer = false;
        } else {
            const normalizedHeader = authorization.toLowerCase();
            return normalizedHeader === scheme || normalizedHeader.startsWith(`${scheme} `);
        }
    }

    return answer;
}

/**
 * Temporarily clears the user.  We call this before every passport
 * authenticator, because passport's session strategy will just set
 * req.user and then call `pass()` instead of `success()`.
 *
 * @param req - The incoming HTTP request.
 * @param originalCallback - The original callback.
 * @returns - A new callback which will restore `req.user` and then call the
 *   original callback.
 */
function clearUser(
    req: any,
    originalCallback: Callback<AuthenticationResult>
) : Callback<AuthenticationResult> {
    const origUser = req.user;
    req.user = undefined;

    return (err: Error | null | undefined, result?: AuthenticationResult) => {
        req.user = origUser;
        originalCallback(err, result);
    };
}

function generateSuccessResult(
    pluginContext: ExegesisPluginContext,
    converter: PassportUserToExegesisUserFn,
    user: any
) {
    const result : AuthenticationSuccess = Object.assign(
        {type: 'success'} as {type: 'success'},
        converter(user, pluginContext)
    );
    return result;
}

function getTypeOnFailure(
    options: Options,
    pluginContext: ExegesisPluginContext,
    info: AuthenticatorInfo
) {
    let type: 'missing' | 'invalid';
    if(!options.isPresent) {
        type = defaultIsPresent(pluginContext, info) ? 'invalid' : 'missing';
    } else if(!options.isPresent(pluginContext, info)) {
        type = 'missing';
    } else {
        type = 'invalid';
    }

    return type;
}

/**
 * Create a new Exegesis authenticator from a passport instance.
 *
 * @param passport - The passport instance to call into.  This should be installed
 *   in your middleware chain before exegesis with `app.use(passport.initialize())`.
 * @param strategyName - The name of the passport strategy to use.  This strategy
 *   should be registered with passport with `passport.use(...)`.
 * @param options - options to pass to strategy.
 * @param converter - A function to convert Passport users into
 *   `{user, roles, scopes}` objects.  If not defined, `user.roles` will be used
 *   as roles, and `user.scopes` will be used as scopes.
 * @returns - An Exegesis authenticator.
 */
function makePassportAuthenticator(
    passport: passport.Authenticator,
    strategyName: string,
    options: Options = {}
) : Authenticator {
    const converter = options.convert || defaultConverter;
    return function passportAuthenticator(
        pluginContext: ExegesisPluginContext,
        info: AuthenticatorInfo,
        done
    ) {
        const req: any = pluginContext.req;

        const origDone = clearUser(req, done);
        done = (err: Error | null | undefined, result?: AuthenticationResult) => {
            if(err) {
                origDone(err);
            } else if(!(result && result.type === 'success') && req.user) {
                // Passport didn't give us a user, but it did set req.user.
                // The session middleware does this.
                origDone(null, generateSuccessResult(pluginContext, converter, req.user));
            } else {
                origDone(err, result);
            }
        };

        passport.authenticate(strategyName, options.passportOptions || {}, (err, user, challenge, status) => {
            if(err) {
                done(err);

            } else if(user) {
                done(null, generateSuccessResult(pluginContext, converter, user));

            } else {
                const type = getTypeOnFailure(options, pluginContext, info);
                const result : AuthenticationFailure = { type, status };

                if(challenge && isString(challenge)) {
                    result.challenge = challenge;
                } else if(challenge && challenge.message) {
                    result.message = challenge.message;
                }

                done(null, result);
            }
        })(pluginContext.req, pluginContext.origRes, done);
    };
}

/**
 * Create a new Exegesis authenticator from a passport strategy.
 *
 * @param strategy - An instance of a Passport strategy to call.  Passport
 *   does not need to be registered as a middleware for this to work.
 * @param options - options to pass to strategy.
 * @param converter - A function to convert Passport users into
 *   `{user, roles, scopes}` objects.  If not defined, `user.roles` will be used
 *   as roles, and `user.scopes` will be used as scopes.
 * @returns - An Exegesis authenticator.
 */
function makeStrategyRunner(
    strategy: Strategy,
    options: Options = {}
) : Authenticator {
    return function passportStrategyAuthenticator(
        pluginContext: ExegesisPluginContext,
        info: AuthenticatorInfo,
        done
    ) {
        const req: any = pluginContext.req;
        const converter = options.convert || defaultConverter;
        done = clearUser(req, done);

        runStrategy(strategy, pluginContext.req, options.passportOptions, (err, result) => {
            if(err || !result) {
                return done(err);
            }

            switch(result.type) {
                case 'success': {
                    done(null, generateSuccessResult(pluginContext, converter, result.user));
                    break;
                }
                case 'pass':
                    if(req.user) {
                        // Passport didn't give us a user, but it did set req.user.
                        // The session middleware does this.
                        done(null, generateSuccessResult(pluginContext, converter, req.user));
                    } else {
                        done(null, undefined);
                    }
                    break;
                case 'fail':
                    const answer : AuthenticationFailure = {
                        type: getTypeOnFailure(options, pluginContext, info),
                        status: result.status,
                        challenge: result.challenge,
                        message: result.message
                    };
                    done(null, answer);
                    break;
                case 'redirect': {
                    const {res} = pluginContext;
                    res.setStatus(result.status)
                        .set('location', result.url)
                        .setBody('');
                    done(null, undefined);
                    break;
                }
                /* istanbul ignore next */
                default:
                    assertNever(result);
            }
        });
    };
}

/**
 * Create a new Exegesis authenticator from a passport instance.
 *
 * @param passport - The passport instance to call into.  This should be installed
 *   in your middleware chain before exegesis with `app.use(passport.initialize())`.
 * @param strategyName - The name of the passport strategy to use.  This strategy
 *   should be registered with passport with `passport.use(...)`.
 * @param options.converter - A function to convert Passport users into
 *   `{user, roles, scopes}` objects.  If not defined, `user.roles` will be used
 *   as roles, and `user.scopes` will be used as scopes.
 * @param options.isPresent - A function to check if the authentication
 *   scheme was attempted or not.
 * @param options.passportOptions - Options to pass to the passport strategy.
 * @returns - An Exegesis authenticator.
 */
export function exegesisPassport(
    passport: passport.Authenticator,
    strategyName: string,
    options?: Options
) : Authenticator;

/**
 * Create a new Exegesis authenticator from a passport strategy.
 *
 * @param strategy - An instance of a Passport strategy to call.  Passport
 *   does not need to be registered as a middleware for this to work.
 * @param options.converter - A function to convert Passport users into
 *   `{user, roles, scopes}` objects.  If not defined, `user.roles` will be used
 *   as roles, and `user.scopes` will be used as scopes.
 * @param options.isPresent - A function to check if the authentication
 *   scheme was attempted or not.
 * @param options.passportOptions - Options to pass to the passport strategy.
 * @returns - An Exegesis authenticator.
 */
export function exegesisPassport(
    strategy: Strategy,
    options?: Options
) : Authenticator;

export function exegesisPassport(
    a: passport.Authenticator | Strategy,
    b?: any,
    c?: Options
) {
    if(isPassportAuthenticator(a) && isString(b)) {
        return makePassportAuthenticator(a, b, c);
    } else {
        return makeStrategyRunner(a as Strategy, b as Options);
    }
}

export default exegesisPassport;