// File is an authentication that takes users from a yaml file
// Example :
//   - username: admin
//     password: $2y$10$ro2aBKU9jyqfokF2arnaEO3GKmAawnfLfEFq1dGuGl9CYEutrxGCa
//   - username: test
//     password: $2y$10$ro2aBKU9jyqfokF2arnaEO3GKmAawnfLfEFq1dGuGl9CYEutrxGCa
//
// To generate a password, you can use htpasswd command :
//
// ❯ htpasswd -bnBC 10 "" hupload
// :$2y$10$AJEytAoJfc4yQjUS8/cG6eXADlgK/Dt3AvdB0boPJ7EcHofewGQIK
//
// and remove the leading `:` from the hash
package file
