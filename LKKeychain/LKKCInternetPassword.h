//
//  LKKCInternetPassword.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright © 2011, Károly Lőrentey. All rights reserved.
//  
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//  
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above
//    copyright notice, this list of conditions and the following
//    disclaimer in the documentation and/or other materials provided
//    with the distribution.
//  * Neither the name of Károly Lőrentey nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//  
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
//  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL KÁROLY LŐRENTEY BE LIABLE FOR ANY
//  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
//  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 

#import <LKKeychain/LKKCKeychainItem.h>

typedef enum {
    LKKCAuthenticationTypeAny,
    LKKCAuthenticationTypeNTLM,
    LKKCAuthenticationTypeMSN,
    LKKCAuthenticationTypeDPA,
    LKKCAuthenticationTypeRPA,
    LKKCAuthenticationTypeHTTPBasic,
    LKKCAuthenticationTypeHTTPDigest,
    LKKCAuthenticationTypeHTMLForm,
    LKKCAuthenticationTypeDefault  
} LKKCAuthenticationType;

/** Supported protocol types.
 */
typedef enum {
    LKKCProtocolAny,
    LKKCProtocolFTP,
    LKKCProtocolFTPAccount,
    LKKCProtocolHTTP,
    LKKCProtocolIRC,
    LKKCProtocolNNTP,
    LKKCProtocolPOP3,
    LKKCProtocolSMTP,
    LKKCProtocolSOCKS,
    LKKCProtocolIMAP,
    LKKCProtocolLDAP,
    LKKCProtocolAppleTalk,
    LKKCProtocolAFP,
    LKKCProtocolTelnet,
    LKKCProtocolSSH,
    LKKCProtocolFTPS,
    LKKCProtocolHTTPS,
    LKKCProtocolHTTPProxy,
    LKKCProtocolHTTPSProxy,
    LKKCProtocolFTPProxy,
    LKKCProtocolSMB,
    LKKCProtocolRTSP,
    LKKCProtocolRTSPProxy,
    LKKCProtocolDAAP,
    LKKCProtocolEPPC,
    LKKCProtocolIPP,
    LKKCProtocolNNTPS,
    LKKCProtocolLDAPS,
    LKKCProtocolTelnetS,
    LKKCProtocolIMAPS,
    LKKCProtocolIRCS,
    LKKCProtocolPOP3S
} LKKCProtocol;

/** Represents an internet password in a keychain.
 
 Internet passwords associate a password with a URL, extended by an optional authentication type 
 and security domain string.
 
 The URL is not stored directly on the keychain; it is instead split up into its components:
 protocol, account, server, port, and path.  Each of these components is stored separately in 
 its own attribute. 
 
 <LKKCInternetPassword> has separate readwrite properties for all these components.
 As a shortcut, it also provides <[LKKCInternetPassword url]> that reads all component properties 
 and builds an `NSURL` instance from them, or (when set) splits the URL into components and
 assigns them to the corresponding attributes.
 
     LKKCInternetPassword *item = [LKKCInternetPassword createPassword];
     item.url = [NSURL urlWithString:@"http://username@example.com:8080/admin/login.php"];
     item.authenticationType = LKKCAuthenticationTypeHTMLBasic;
     item.securityDomain = @"Administration Interface";
     item.password = @"bananas";
 
     LKKCKeychain *keychain = [LKKCKeychain defaultKeychain];
     result = [item addToKeychain:keychain withError:NULL];
     if (!result) {
         // Oops
     }
 
 To retrieve a password for a URL, iterate over all passwords with the same server, 
 and find the one that's the best match.
 
     LKKCKeychain *keychain = [LKKCKeychain defaultKeychain];
     for (LKKCInternetPassword *item in [keychain internetPasswordsForServer:@"example.com"]) {
         if (item.authenticationType == LKKCAuthenticationTypeHTMLBasic
             && [item.securityDomain isEqualToString:@"Administration Interface"]) {
             return item.password;
         }
     }
 
*/
@interface LKKCInternetPassword : LKKCKeychainItem

/** Returns the string representation of an authentication type value.
 
 @param authenticationType The authentication type value to convert to a string.
 @return A short string that corresponds to the given authentication type value. (E.g., `HTTPBasic` for `LKKCAuthenticationTypeHTTPBasic`.)
 */
+ (NSString *)stringFromAuthenticationType:(LKKCAuthenticationType)authenticationType;

/** Returns the URL scheme for a protocol value.
 
 If the protocol does not have a canonical URL scheme, this methods returns a nonstandard value.
 For example, `LKKCProtocolFTP` is converted to its well-known, standard scheme `ftp`, while
 `LKKCProtocolHTTPProxy` (not a real protocol) is converted to the nonstandard scheme `http-proxy`.
 `LKKCProtocolAny` is the special protocol value that matches all protocols; its nonstandard scheme is `any`.
 
 @param protocol A protocol value.
 @return The URL scheme for the given protocol value.
 */
+ (NSString *)urlSchemeFromProtocol:(LKKCProtocol)protocol;

/** --------------------------------------------------------------------------------
 @name Creating new passwords
 -------------------------------------------------------------------------------- */

/** Creates a new, empty internet password item.
 
 The item must be initialized by assigning to its properties.
 You can use <[LKKCKeychainItem addToKeychain:error:]> to save the newly created password on a keychain.
 */
+ (LKKCInternetPassword *)createPassword;

/** --------------------------------------------------------------------------------
 @name Accessing the password value
 -------------------------------------------------------------------------------- */

/** The password value.
 
 The property getter returns nil when access was denied to this application.
 */
@property (nonatomic, retain) NSString *password;

/** Returns the password value.
 @param error On output, the error that occurred in case the password could not be accessed (optional).
 @return The password stored in this item, or nil when access was denied.
 */
- (NSString *)passwordWithError:(NSError **)error;

/** --------------------------------------------------------------------------------
 @name URL-based attribute access
 -------------------------------------------------------------------------------- */

/** The URL for this internet password. */
@property (nonatomic, copy) NSURL *url;

/** --------------------------------------------------------------------------------
 @name URL component attributes
 -------------------------------------------------------------------------------- */

/** Protocol.
 
 The following values are supported:
 
 - `LKKCProtocolAny` -- Matches all protocols.
 - `LKKCProtocolFTP` -- File Transfer Protocol.
 - `LKKCProtocolFTPAccount` -- Client side FTP account.
 - `LKKCProtocolHTTP` -- Hypertext Transfer Protocol.
 - `LKKCProtocolIRC` -- Internet Relay Chat.
 - `LKKCProtocolNNTP` -- Network News Transfer Protocol.
 - `LKKCProtocolPOP3` -- Post Office Protocol 3.
 - `LKKCProtocolSMTP` -- Simple Mail Transfer Protocol.
 - `LKKCProtocolSOCKS` -- SOCKS proxy authentication.
 - `LKKCProtocolIMAP` -- Internet Mail Access Protocol.
 - `LKKCProtocolLDAP` -- Lightweight Directory Access Protocol.
 - `LKKCProtocolAppleTalk` -- Apple Filing Protocol over AppleTalk.
 - `LKKCProtocolAFP` -- Apple Filing Protocol over IP.
 - `LKKCProtocolTelnet` -- Telnet protocol.
 - `LKKCProtocolSSH` -- Secure Shell.
 - `LKKCProtocolFTPS` -- FTP with TLS/SSL.
 - `LKKCProtocolHTTPS` -- HTTP with TLS/SSL.
 - `LKKCProtocolHTTPProxy` -- HTTP proxy password.
 - `LKKCProtocolHTTPSProxy` -- HTTPS proxy password.
 - `LKKCProtocolFTPProxy` -- FTP proxy password.
 - `LKKCProtocolSMB` -- Server Message Block (SMB/CIFS).
 - `LKKCProtocolRTSP` -- Real Time Streaming Protocol.
 - `LKKCProtocolRTSPProxy` -- RTSP proxy password.
 - `LKKCProtocolDAAP` -- Digital Audio Access Protocol.
 - `LKKCProtocolEPPC` -- Remote Apple Events.
 - `LKKCProtocolIPP` -- Internet Printing Protocol.
 - `LKKCProtocolNNTPS` -- NNTP with TLS/SSL.
 - `LKKCProtocolLDAPS` -- LDAP with TLS/SSL.
 - `LKKCProtocolTelnetS` -- Telnet with TLS/SSL.
 - `LKKCProtocolIMAPS` -- IMAP with TLS/SSL.
 - `LKKCProtocolIRCS` -- IRC with TLS/SSL.
 - `LKKCProtocolPOP3S` -- POP3 with TLS/SSL.

 Use `LKKCProtocolAny` if your protocol isn't listed above.
 
 This property corresponds to the `kSecAttrProtocol` attribute.
 
 This property is a primary key for generic password items. 
 Modifying it may invalidate previously generated persistent IDs that refer to this item.
 */
@property (nonatomic, assign) LKKCProtocol protocol;

/** Account name, a.k.a. username.
 
 This property corresponds to the `kSecAttrAccount` attribute.
 
 This property is a primary key for generic password items. 
 Modifying it may invalidate previously generated persistent IDs that refer to this item.
 */
@property (nonatomic, retain) NSString *account;

/** Server name, a.k.a hostname.

 This property corresponds to the `kSecAttrServer` attribute.

 This property is a primary key for generic password items. 
 Modifying it may invalidate previously generated persistent IDs that refer to this item.
 */
@property (nonatomic, retain) NSString *server;

/** Port number, or 0 if unspecified.

 This property corresponds to the `kSecAttrPort` attribute.
 
 This property is a primary key for generic password items. 
 Modifying it may invalidate previously generated persistent IDs that refer to this item.
 */
@property (nonatomic, assign) int port;

/** Resource path.

 This property corresponds to the `kSecAttrPath` attribute.
 
 This property is a primary key for generic password items. 
 Modifying it may invalidate previously generated persistent IDs that refer to this item.
 */
@property (nonatomic, assign) NSString *path;

/** --------------------------------------------------------------------------------
 @name Security domain and authentication type
 -------------------------------------------------------------------------------- */

/** Security domain.
 
 The domain is additional information that identifies the scope of this password.
 For example, the realm value in HTTP Basic Authentication is stored in this attribute.

 This property corresponds to the `kSecAttrSecurityDomain` attribute.

 This property is a primary key for generic password items. 
 Modifying it may invalidate previously generated persistent IDs that refer to this item.
 */
@property (nonatomic, retain) NSString *securityDomain;

/** Authentication type.
 
 The following authentication types are supported:
 
 - `LKKCAuthenticationTypeAny` -- Matches all authentication types.
 - `LKKCAuthenticationTypeNTLM` -- Windows NT LAN Manager authentication.
 - `LKKCAuthenticationTypeMSN` -- Microsoft Network default authentication.
 - `LKKCAuthenticationTypeDPA` -- Distributed Password authentication.
 - `LKKCAuthenticationTypeRPA` -- Remote Password authentication.
 - `LKKCAuthenticationTypeHTTPBasic` -- HTTP Basic authentication.
 - `LKKCAuthenticationTypeHTTPDigest` -- HTTP Digest authentication.
 - `LKKCAuthenticationTypeHTMLForm` -- HTML form password value.
 - `LKKCAuthenticationTypeDefault` -- Default authentication type.

 Use `LKKCAuthenticationTypeAny` if your authentication type isn't listed above.
 
 This property corresponds to the `kSecAttrAuthenticationType` attribute.

 This property is a primary key for generic password items. 
 Modifying it may invalidate previously generated persistent IDs that refer to this item.
  */
@property (nonatomic, assign) LKKCAuthenticationType authenticationType;


/** --------------------------------------------------------------------------------
 @name Generic item attributes
 -------------------------------------------------------------------------------- */

/** A human-readable label for this password. Shows up as "Name" in Keychain Access.
 
 This property corresponds to the `kSecAttrLabel` attribute.
 */
@property (nonatomic, retain) NSString *label;

/** The human-readable item kind ("Internet Password" by default). Shows up as "Kind" in Keychain Access. 
 
 This property corresponds to the `kSecAttrDescription` attribute.
 */
@property (nonatomic, retain) NSString *kind;

/** Human-readable comment. Shows up as "Comments" in Keychain Access.
 
 This property corresponds to the `kSecAttrComment` attribute. 
 */
@property (nonatomic, retain) NSString *comment;

/** Creation date.
 
 This property corresponds to the `kSecAttrCreationDate` attribute.
 */
@property (nonatomic, readonly) NSDate *creationDate;

/** Last modification date. 
 
 This property corresponds to the `kSecAttrModificationDate` attribute.
 */
@property (nonatomic, readonly) NSDate *modificationDate;

/** If YES, the password value isn't displayed in Keychain Access. 
 
 This property corresponds to the `kSecAttrIsInvisible` attribute.
 */
@property (nonatomic, assign, getter = isInvisible) BOOL invisible;

/** If YES, this is a negative item without a password value.
 
 Negative items indicate that the user has explicitly disabled password storage for this account.
 
 This property corresponds to the `kSecAttrIsNegative` attribute. 
 */
@property (nonatomic, assign, getter = isNegative) BOOL negative;

@end

//kSecClassInternetPassword item attributes:
//kSecAttrAccess
//kSecAttrCreator
//kSecAttrType

