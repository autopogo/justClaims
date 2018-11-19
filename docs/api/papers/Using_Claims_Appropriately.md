DRAFT
# How to use claims appropriately

This assumes you already understand the basic functions/ins and outs of claims. The API is tiny (~5 funcs).

## What are claims?

In this case, JSON Web Token claims, are JSON data structures:

```
{
key : value
key : {
				key : value
				key : value
			}
}
```

... which are serialized and signed cryptographically so that wecan verify if we (the server) truly wrote them. We then give them to a user, who can bring them back to us. Usually, they include a couple basic claims: iat (issued at), exp (expires at), etc. They can also have non-standard claims, and encrypted claims. They are passed to the server in the header of every connection, and the server to the client if it wants to adjust them. They are often in cookies, but can also be in the "authorization" header for cookie-less HTTP transfers (most `curl`, for example).

## When can I use them

If you won't need to revoke them, or access that information at a later time. Therefore, they're good if, for example: 

1) They're only relevant to the browser session you're currently in
2) They don't need to be revoked because they're dependent on something else that can be revoked
3) They are for an anonymous user

In this situation, you might consider using claims soley.

## Claims as a cache

The other situations we can use claims is to store a session ID which is then validated on-server. This way, a particular connection can claim a state ID, and we can retrieve and validate the state ID. These are called sessions.

### The whole vision of cache

When you put in claims, you need to put in anonymous vs security claims.

/
Learn relevant claims from init.
// user will include a structure with all claims wanted- new and otherwise- and will learn claim from `tag`- if new.
// keep a list of all claims and refresh them, clear them through marshall/unmarshal as you need to- save them, dump them, whatever
// justClaims will build the list as a private member of your structure
// unmarshal to a structure that you're passed
Only pass back relevant claims.
how do we make sure all claims get written
probably by leveraging the request cookie eh?- but do we have to unmarshal again

/
// claims they can't change
// hook to check cache/refresh- anytime you get claims you have to check cache,
// and refresh if you rewrite them
// populate a couple different structures
// return a structure associated with that file
// all structure should have interface{} to point to other members
	// how do you make sure you're not writing the same member twice?

Claims/Database/RAM

We have one offset list where we map offset to time of cache expiry. This is so we know that all programs need to regrab any user-identifying info. This can also log users out universally. But if you say you're the user otherwise, you're the user.

We have a session offset list that has three global head-tails pairs -one for time 1 (90 min), one for time 2 (1 week), 1 for free spaces. I guess '0' has to be blank. Each entry has two thirty-two bit head-tail numbers, 

If we have big networks, we can use REST, but invalidate entire groups of networks and force them to re-update their credentials. We can call that a group session. But we don't maintain individual sessions, I don't think. I think IoT devices are gonna have massive data needs tho. Like they gotta store a lot of data.

#### User login:
 // we're going to mainline authenticate the user
 // we give a username, and we give a loginkey
 // We're also going to create a session, and put it in the list where it belongs
#### User Authenticate
 // User says who they are.
 // Their login key matches.
 // Their token is iat > cache valid, so we can leave their claims alone.
 // Their sessions also has to match... 
#### User logout:

#### Permify Session:

#### Depermify Session:

#### Session Expiry:

#### Cache Expiry (user privies change)


#### Universal Claims

uid (user) <-- can be invalidated? No, unless token expires, or _all are signed out forceably_
offset <-- this is the same as the user
offset answers: has cache been changed? has user been forceably signed out?

If we want ultimate security, we have to maintain sessions-->user association in database and when people logout, effect the cache expiry date.
If someone comes in with a good token, claiming to be a user, but paste the expiry date, we should check to make sure the user is still associatedw ith that session.
So they're really session-based caches (anon id), but only apply if you're a user.

anon offset (session)
version <-- not invalidated
iat <-- not invalidated
exp <-- not invalidated

#### Mutual Expiry

If a session expires, it needs to expire both in the claim and in the database, and there might be other resources that should expire/die with it.
Offset ordered linked list
