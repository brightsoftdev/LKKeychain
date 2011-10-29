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
+ (NSString *)stringFromProtocol:(LKKCProtocol)protocol;

//kSecClassInternetPassword item attributes:
//kSecAttrAccess
//kSecAttrCreator
//kSecAttrType

@property (nonatomic, retain) NSString *label; // kSecAttrLabel
@property (nonatomic, retain) NSString *itemDescription; // kSecAttrDescription
@property (nonatomic, retain) NSString *comment; // kSecAttrComment

@property (nonatomic, readonly) NSDate *creationDate; // kSecAttrCreationDate
@property (nonatomic, readonly) NSDate *modificationDate; // kSecAttrModificationDate

@property (nonatomic, assign, getter = isInvisible) BOOL invisible; // kSecAttrIsInvisible
@property (nonatomic, assign, getter = isNegative) BOOL negative; // kSecAttrIsNegative

@property (nonatomic, retain) NSString *account; // kSecAttrAccount
@property (nonatomic, retain) NSString *securityDomain; // kSecAttrSecurityDomain
@property (nonatomic, retain) NSString *server; // kSecAttrServer
@property (nonatomic, assign) LKKCProtocol protocol; // kSecAttrProtocol
@property (nonatomic, assign) LKKCAuthenticationType authenticationType; // kSecAttrAuthenticationType
@property (nonatomic, assign) int port; // kSecAttrPort
@property (nonatomic, assign) NSString *path; // kSecAttrPath

@property (nonatomic, retain) NSString *password;


@end
