//
//  LKKCInternetPassword.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeychainItem.h"

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

@interface LKKCInternetPassword : LKKCKeychainItem

+ (NSString *)stringFromAuthenticationType:(LKKCAuthenticationType)authenticationType;
+ (NSString *)urlSchemeFromProtocol:(LKKCProtocol)protocol;

+ (LKKCInternetPassword *)createPassword;

// The human-readable name of this password. Shows up as "Name" in Keychain Access. (kSecAttrLabel)
@property (nonatomic, retain) NSString *label;

// The human-readable item kind ("Internet Password" by default). Shows up as "Kind" in Keychain Access. (kSecAttrDescription)
@property (nonatomic, retain) NSString *kind;

// Human-readable comment. Shows up as "Comments" in Keychain Access. (kSecAttrComment)
@property (nonatomic, retain) NSString *comment;

// Creation date. (kSecAttrCreationDate)
@property (nonatomic, readonly) NSDate *creationDate;

// Modification date. (KSecAttrModificationDate)
@property (nonatomic, readonly) NSDate *modificationDate;

// If YES, password value doesn't show in Keychain Access. (kSecAttrIsInvisible)
@property (nonatomic, assign, getter = isInvisible) BOOL invisible;

// If YES, item has no password; user has disabled password storage for this account. (kSecAttrIsNegative)
@property (nonatomic, assign, getter = isNegative) BOOL negative;


// Account name, a.k.a. username. (kSecAttrAccount)
@property (nonatomic, retain) NSString *account;
// Security domain (kSecAttrSecurityDomain)
@property (nonatomic, retain) NSString *securityDomain;
// Server name, a.k.a hostname. (kSecAttrServer)
@property (nonatomic, retain) NSString *server;
// Protocol (kSecAttrProtocol)
@property (nonatomic, assign) LKKCProtocol protocol;
// Authentication type (kSecAttrAuthenticationType)
@property (nonatomic, assign) LKKCAuthenticationType authenticationType;
// Port number, or 0 if unspecified (kSecAttrPort)
@property (nonatomic, assign) int port;
// Resource path (kSecAttrPath)
@property (nonatomic, assign) NSString *path;

@property (nonatomic, copy) NSURL *url;

@property (nonatomic, retain) NSString *password;

@end

//kSecClassInternetPassword item attributes:
//kSecAttrAccess
//kSecAttrCreator
//kSecAttrType

