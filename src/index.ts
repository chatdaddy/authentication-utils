import got from 'got'
import JWT from 'jsonwebtoken'
import NodeCache from 'node-cache'
import querystring from 'querystring'
import { URL } from 'url'
import { STATUS_CODES } from 'http'

const DEF_TOKEN_EXPIRY = 60 // in minutes
const PUBLIC_KEY = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEevVHEB81+mIuHJ6Ka2+GveuyAb2P
SNEGnm4K1V6HzZF0F9+mQS7N0UHNE+gv0OQIKi5D6e48ZCVytj3iX4Todg==
-----END PUBLIC KEY-----
`

export type AuthenticationController = ReturnType<typeof makeAuthenticationController>

export type ChatDaddyAPIUser = {
    identifier: string
    teamId: string
    userId: string
    serviceId: string
    token: string
    /** Binary encoded string */
    scope: string
}
export type TeamDetails = {
    id: string
    name: string
    userId?: string
    teamOwner?: string
}

export const makeAuthenticationController = (refreshToken: string, baseUrl?: string) => {
    baseUrl = baseUrl || process.env.AUTH_SERVICE_URL
    refreshToken = refreshToken
    const tokenCache = new NodeCache ({ stdTTL: DEF_TOKEN_EXPIRY*60 - 1 })

    const getToken = (teamId: string) => {
        let task: Promise<string> = tokenCache.get(teamId)
        if(!task) {
            task = (async () => {
                const url = new URL('oauth/token', baseUrl)
                const requestBody = {
                    refresh_token: refreshToken,
                    team_id: teamId,
                    grant_type: 'refresh_token',
                    expiration: DEF_TOKEN_EXPIRY
                }
                const response = await got.post (url, { 
                    body: querystring.encode (requestBody), 
                    headers: { 'content-type': 'application/x-www-form-urlencoded' } 
                })
                const responseJSON = JSON.parse(response.body)
                return responseJSON.accessToken as string
            })()
            tokenCache.set(teamId, task)
        }
        return task
    }
    
    return {
        // authenticates a token
        authenticate: (token: string) => {
            const user: any = JWT.verify(token, PUBLIC_KEY, { algorithms: [ 'ES256' ] })
            const teamId = user.user.teamId
            const serviceId = user.user.teamOwner
            return {
                userId: user.user.id,
                teamId,
                serviceId,
                token,
                scope: user.scope,
                identifier: teamId
            } as ChatDaddyAPIUser
        },
        // fetches a token for a given teamId
        getToken,
        getTeamDetails: async(teamId: string) => {
            const token = await getToken(teamId)
            const url = new URL('teams?request_type=admin&id=' + teamId, process.env.AUTH_SERVICE_URL)
            const response = await got.get(url, { headers: { 'Authorization': `Bearer ${token}` } })
            const responseJSON = JSON.parse(response.body)
            return responseJSON.meta[0] as TeamDetails
        }
    }
}
/**
 * @param scopes Authorizes if any of the scopes match
 */
export const Authorize = (...scopes: number[]) => (
    (req, res, next) => {
        const authorized = isUserAuthorized(req.user, scopes)
        if (authorized) {
            next()
        } else {
            res.status(403).send(
                { 
                    code: 403, 
                    error: 'You don\'t have access to this method', 
                    message: STATUS_CODES[403] 
                }
            )
        }
    }
)

export const isUserAuthorized = (user: ChatDaddyAPIUser, scopes: number[]) => {
    const userScopes: string = user.scope
    const authorized = scopes.filter(idx => userScopes[idx] !== '1').length < scopes.length
    return authorized
}