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

@property (nonatomic, readonly) LKKCKey *publicKey;

@property (nonatomic, retain) NSString *label; // kSecAttrLabel

@property (nonatomic, readonly) NSData *subject; // kSecAttrSubject
@property (nonatomic, readonly) NSData *issuer; // kSecAttrIssuer
@property (nonatomic, readonly) NSData *serialNumber; // kSecAttrSerialNumber
@property (nonatomic, readonly) NSData *subjectKeyID; // kSecAttrSubjectKeyID
@property (nonatomic, readonly) NSData *publicKeyHash; // kSecAttrPublicKeyHash

@property (nonatomic, readonly) id certificateType; // kSecAttrCertificateType
@property (nonatomic, readonly) id certificateEncoding; // kSecAttrCertificateEncoding

@property (nonatomic, readonly) NSString *commonName;
@property (nonatomic, readonly) NSString *subjectSummary;
@property (nonatomic, readonly) NSArray *emailAddresses;

@property (nonatomic, readonly) SecCertificateRef SecCertificate;

@end
