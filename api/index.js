import { common } from "@nfjs/core";
import { authProviders } from "../index.js";

class NFAuth {
    async login(user, password, session) {
        const log = [];
        let p;
        for (p in authProviders) {
            try {
                const r = await authProviders[p].login(user, password, session);
                if (r.result) {
                    session.set('authProvider', p);
                    return r;
                }

                log.push({ provider: p, result: r });
            } catch (e) {
                log.push({ provider: p, result: { result: false, detail: e.message } });
            }
        }
        return { result: false, detail: log };
    }

    async logout(session) {
        if (session.get('authProvider')) {
            return authProviders[session.get('authProvider')].logout(session);
        }
    }

    static requestCheck(req, res, next) {
        if (common.getPath(req, 'cachedObj.attributes.unauthorized') === undefined && !req.session.authProvider) {
            res.sendStatus(401);
            return;
        }
        next();
    }

    getUserInfo(session, params) {
        if (session.get('authProvider')) {
            return authProviders[session.get('authProvider')].getUserInfo(session, params);
        }
        return {};
    }

    static async authMiddleware(context) {
        const authProvider = authProviders[context.session.get('authProvider')];
        if (!authProvider) {
            context.code(401);
            context.end();
            return false;
        } else {
            if ('validate' in authProvider) {
                const resValidate = await authProvider.validate(context.session);
                if (resValidate === false) {
                    await authProvider.logout(context.session);
                    context.code(401);
                    context.end();
                    return false;
                }
            }
        }
    }
}

export default NFAuth;