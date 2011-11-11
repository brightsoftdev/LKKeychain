//
//  LKKCCertificate.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeychainItem.h"

@class LKKCKey;
@interface LKKCCertificate : LKKCKeychainItem

+ (LKKCCertificate *)certificateWithDERData:(NSData *)data;
+ (LKKCCertificate *)certificateWithSecCertificate:(SecCertificateRef)scertificate;

//- (BOOL)validate;
//- (BOOL)validateForSSLServer:(NSString *)hostname;
//- (BOOL)validateForEmailAddress:(NSString *)emailAddress;

@property (nonatomic, readonly) LKKCKey *publicKey;

// The human-readable name of this certificate. Shows up as "Name" in Keychain Access. (kSecAttrLabel)
@property (nonatomic, retain) NSString *label;

// The normalized subject of this certificate. (kSecAttrSubject)
@property (nonatomic, readonly) NSData *subject;

// The normalized issuer of this certificate. (kSecAttrIssuer)
@property (nonatomic, readonly) NSData *issuer;

// The serial numbr of this certificate. (kSecAttrSerialNumber)
@property (nonatomic, readonly) NSData *serialNumber;

// The subject key ID of this certificate. (kSecAttrSubjectKeyID)
@property (nonatomic, readonly) NSData *subjectKeyID;

// The SHA-1 hash of this certificate's public key. (kSecAttrPublicKeyHash)
@property (nonatomic, readonly) NSData *publicKeyHash;

// The type of this certificate (kSecAttrCertificateType)
@property (nonatomic, readonly) id certificateType;

// The encoding of this certificate (kSecAttrCertificateEncoding)
@property (nonatomic, readonly) id certificateEncoding;


// The Common Name of the certificate subject.
@property (nonatomic, readonly) NSString *commonName;

// Human-readable summary of certificate subject.
@property (nonatomic, readonly) NSString *subjectSummary;

// Email addresses included in the certificate subject.
@property (nonatomic, readonly) NSArray *emailAddresses;

// Certificate data in DER format.
@property (nonatomic, readonly) NSData *data;

@property (nonatomic, readonly) SecCertificateRef SecCertificate;

@end
