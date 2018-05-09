import { runStrategy } from 'passport-strategy-runner';
import { Strategy } from 'passport-strategy';
import * as passport from 'passport';
import * as exegesis from 'exegesis';

export interface PassportToExegesisRolesFn {
    (
        user: any,
        pluginContext: exegesis.ExegesisPluginContext
    ) : exegesis.ExegesisAuthenticated;
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
        passport.authorize(strategyName, (err, user, challenge, status) => {
            if(err) {
                done(err);
            } else if(user) {
                const result = converter(user, pluginContext);
                if(!result.user) {result.user = user;}
                done(null, result);
            } else {
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
        runStrategy(strategy, pluginContext.req, (err, result) => {
            if(err || !result) {
                return done(err);
            }

            switch(result.type) {
                case 'success': {
                    const answer = converter(result.user, pluginContext);
                    if(!answer.user) {answer.user = result.user;}
                    done(null, answer);
                    break;
                }
                case 'pass':
                    done(null, undefined);
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