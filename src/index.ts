import { runStrategy } from 'passport-strategy-runner';
import { Strategy } from 'passport-strategy';
import * as passport from 'passport';
import * as exegesis from 'exegesis';

export type PassportToExegesisResult =
    (Pick<exegesis.AuthenticationSuccess, 'user' | 'roles' | 'scopes'>) |
    {[prop: string]: any};

export interface PassportToExegesisRolesFn {
    (
        user: any,
        pluginContext: exegesis.ExegesisPluginContext
    ) : PassportToExegesisResult;
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
    originalCallback: exegesis.Callback<exegesis.AuthenticationResult>
) : exegesis.Callback<exegesis.AuthenticationResult> {
    const origUser = req.user;
    req.user = undefined;

    return (err: Error | null | undefined, result?: exegesis.AuthenticationResult) => {
        req.user = origUser;
        originalCallback(err, result);
    };
}

function generateSuccessResult(
    pluginContext: exegesis.ExegesisPluginContext,
    converter: PassportToExegesisRolesFn,
    user: any
) {
    const result : exegesis.AuthenticationSuccess = Object.assign(
        {type: 'success'} as {type: 'success'},
        converter(user, pluginContext)
    );
    return result;
}

/**
 * Create a new Exegesis authenticator from a passport instance.
 *
 * @param passport - The passport instance to call into.  This should be installed
 *   in your middleware chain before exegesis with `app.use(passport.initialize())`.
 * @param strategyName - The name of the passport strategy to use.  This strategy
 *   should be registered with passport with `passport.use(...)`.
 * @param converter - A function to convert Passport users into
 *   `{user, roles, scopes}` objects.  If not defined, `user.roles` will be used
 *   as roles, and `user.scopes` will be used as scopes.
 * @returns - An Exegesis authenticator.
 */
function makePassportAuthenticator(
    passport: passport.Authenticator,
    strategyName: string,
    converter: PassportToExegesisRolesFn = defaultConverter
) : exegesis.Authenticator {
    return function passportAuthenticator(
        pluginContext: exegesis.ExegesisPluginContext,
        done
    ) {
        const req: any = pluginContext.req;

        const origDone = clearUser(req, done);
        done = (err: Error | null | undefined, result?: exegesis.AuthenticationResult) => {
            if(err) {
                origDone(err);
            } else if((!result || (result && result.type === 'fail')) && req.user) {
                // Passport didn't give us a user, but it did set req.user.
                // The session middleware does this.
                origDone(null, generateSuccessResult(pluginContext, converter, req.user));
            } else {
                origDone(err, result);
            }
        };

        passport.authorize(strategyName, (err, user, challenge, status) => {
            if(err) {
                done(err);

            } else if(user) {
                done(null, generateSuccessResult(pluginContext, converter, user));

            } else {
                const result : exegesis.AuthenticationFailure = {
                    type: 'fail',
                    status
                };

                if(challenge && isString(challenge)) {
                    result.challenge = challenge;
                } else if(challenge && challenge.message) {
                    result.message = challenge.message;
                }

                done(null, {type: 'fail', challenge, status});
            }
        })(pluginContext.req, pluginContext.origRes, done);
    };
}

/**
 * Create a new Exegesis authenticator from a passport strategy.
 *
 * @param strategy - An instance of a Passport strategy to call.  Passport
 *   does not need to be registered as a middleware for this to work.
 * @param converter - A function to convert Passport users into
 *   `{user, roles, scopes}` objects.  If not defined, `user.roles` will be used
 *   as roles, and `user.scopes` will be used as scopes.
 * @returns - An Exegesis authenticator.
 */
function makeStrategyRunner(
    strategy: Strategy,
    converter: PassportToExegesisRolesFn = defaultConverter
) : exegesis.Authenticator {
    return function passportStrategyAuthenticator(
        pluginContext: exegesis.ExegesisPluginContext,
        done
    ) {
        const req: any = pluginContext.req;
        done = clearUser(req, done);

        runStrategy(strategy, pluginContext.req, (err, result) => {
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
                    done(null, result);
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
 * @param converter - A function to convert Passport users into
 *   `{user, roles, scopes}` objects.  If not defined, `user.roles` will be used
 *   as roles, and `user.scopes` will be used as scopes.
 * @returns - An Exegesis authenticator.
 */
export function exegesisPassport(
    passport: passport.Authenticator,
    strategyName: string,
    converter?: PassportToExegesisRolesFn
) : exegesis.Authenticator;

/**
 * Create a new Exegesis authenticator from a passport strategy.
 *
 * @param strategy - An instance of a Passport strategy to call.  Passport
 *   does not need to be registered as a middleware for this to work.
 * @param converter - A function to convert Passport users into
 *   `{user, roles, scopes}` objects.  If not defined, `user.roles` will be used
 *   as roles, and `user.scopes` will be used as scopes.
 * @returns - An Exegesis authenticator.
 */
export function exegesisPassport(
    strategy: Strategy,
    converter?: PassportToExegesisRolesFn
) : exegesis.Authenticator;

export function exegesisPassport(
    a: passport.Authenticator | Strategy,
    b?: string | PassportToExegesisRolesFn,
    converter?: PassportToExegesisRolesFn
) {
    if(isPassportAuthenticator(a) && isString(b)) {
        return makePassportAuthenticator(a, b, converter);
    } else {
        return makeStrategyRunner(a as Strategy, b as PassportToExegesisRolesFn);
    }
}

export default exegesisPassport;