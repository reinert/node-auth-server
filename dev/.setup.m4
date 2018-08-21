#!/bin/bash

# m4_ignore(
echo "This is just a script template, not the script (yet) - pass it to 'argbash' to fix this." >&2
exit 11  #)Created by argbash-init v2.7.1
# ARG_OPTIONAL_SINGLE([cors-origin], [c], [CORS accepted origins; comma separated value])
# ARG_OPTIONAL_SINGLE([enc-key], [e], [Key for refresh token encryption])
# ARG_OPTIONAL_SINGLE([key], [k], [Private key for access token signing])
# ARG_OPTIONAL_SINGLE([pub-key], [K], [Public key for access token verification])
# ARG_OPTIONAL_SINGLE([access-exp], [a], [Access Token expiration time in seconds], [86400])
# ARG_OPTIONAL_SINGLE([refresh-exp], [r], [Refresh Token expiration time in seconds], [259200])
# ARG_OPTIONAL_SINGLE([issuer], [i], [Tokens' issuer])
# ARG_OPTIONAL_SINGLE([port], [p], [Server port], [3001])
# ARG_HELP([<Setup needed files to development>])
# ARGBASH_GO

# [ <-- needed because of Argbash

printf 'Value of --%s: %s\n' 'cors-origin' "$_arg_cors_origin"
printf 'Value of --%s: %s\n' 'enc-key' "$_arg_enc_key"
printf 'Value of --%s: %s\n' 'key' "$_arg_key"
printf 'Value of --%s: %s\n' 'pub-key' "$_arg_pub_key"
printf 'Value of --%s: %s\n' 'access-exp' "$_arg_access_exp"
printf 'Value of --%s: %s\n' 'refresh-exp' "$_arg_refresh_exp"
printf 'Value of --%s: %s\n' 'issuer' "$_arg_issuer"
printf "Value of '%s': %s\\n" 'port' "$_arg_port"

# ] <-- needed because of Argbash
