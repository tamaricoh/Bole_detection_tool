# BOLA Attack Detection Tool

This tool parses server logs to detect **Broken Object Level Authorization (BOLA)** attacks. It identifies unauthorized access attempts to sensitive endpoints like `/balance`, `/getusers`, and `/accounts`, and printing out these activities.

The utility is covering two potential BOLA attacks surfaces. One, is an attempt made by the user to perform an API operation which is permitted only for admin role. Second, is an attempt by a user to perform `getBalance` API operation of an account that does not belong to the user.

In both cases, the utility is searching for a `200` responses, helping to identify unauthorized access. The utility differentiates between the types of attacks by the URL. For example, an unauthorized GET request with URL of `/balance?user_id=<number>` points at an attempt of a user trying to accsess another user info.

## Additional potential attack surfaces to cover next (not yet implemented)

1. Registering as an admin seems to be too easy. The utility should be enhanced to alert when, for example, the first register user is not admin, or, there are more then one admin.

2. Rate limitting: The utility should be enhanced to detect repetitive API accesses containing the same request, in a short period of time.

3. User ID guessing attacks: The scheme of uid generation in the system is very weak, and it is easy to guess the next user ID. Just add one to the last one. And given a valid user ID, it is easy to guess another valid user ID. Just decrease one or two. The utility should be able to detect an attemp to guess a valid user ID. It can be done by trying to detect a sequential user IDs that are being repetitively attempted.
