//
//  LKKCCertificate.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright © 2011, Károly Lőrentey. All rights reserved.
//  
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are met:
//  
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//  * Neither the name of Károly Lőrentey nor the names of its contributors 
//    may be used to endorse or promote products derived from this software 
//    without specific prior written permission.
//  
//  **This software is provided by the copyright holders and contributors "as is" and
//  any express or implied warranties, including, but not limited to, the implied
//  warranties of merchantability and fitness for a particular purpose are
//  disclaimed. In no event shall Károly Lőrentey be liable for any
//  direct, indirect, incidental, special, exemplary, or consequential damages
//  (including, but not limited to, procurement of substitute goods or services;
//  loss of use, data, or profits; or business interruption) however caused and
//  on any theory of liability, whether in contract, strict liability, or tort
//  (including negligence or otherwise) arising in any way out of the use of this
//  software, even if advised of the possibility of such damage.**
// 

#import <LKKeychain/LKKCKeychainItem.h>

@class LKKCKey;

/** Represents a digital certificate. */
@interface LKKCCertificate : LKKCKeychainItem

+ (LKKCCertificate *)certificateWithDERData:(NSData *)data;
+ (LKKCCertificate *)certificateWithSecCertificate:(SecCertificateRef)scertificate;

//- (BOOL)validateWithError:(NSError **)error;
//- (BOOL)validateWithSSLHost:(NSString *)hostname server:(BOOL)server error:(NSError **)error;

@property (nonatomic, readonly) LKKCKey *publicKey;

/// The human-readable name of this certificate. Shows up as "Name" in Keychain Access. (kSecAttrLabel)
@property (nonatomic, retain) NSString *label;

/// The normalized subject of this certificate. (kSecAttrSubject)
@property (nonatomic, readonly) NSData *subject;

/// The normalized issuer of this certificate. (kSecAttrIssuer)
@property (nonatomic, readonly) NSData *issuer;

/// The serial numbr of this certificate. (kSecAttrSerialNumber)
@property (nonatomic, readonly) NSData *serialNumber;

/// The subject key ID of this certificate. (kSecAttrSubjectKeyID)
@property (nonatomic, readonly) NSData *subjectKeyID;

/// The SHA-1 hash of this certificate's public key. (kSecAttrPublicKeyHash)
@property (nonatomic, readonly) NSData *publicKeyHash;

/// The type of this certificate (kSecAttrCertificateType)
@property (nonatomic, readonly) id certificateType;

/// The encoding of this certificate (kSecAttrCertificateEncoding)
@property (nonatomic, readonly) id certificateEncoding;


/// The Common Name of the certificate subject.
@property (nonatomic, readonly) NSString *commonName;

/// Human-readable summary of certificate subject.
@property (nonatomic, readonly) NSString *subjectSummary;

/// Email addresses included in the certificate subject.
@property (nonatomic, readonly) NSArray *emailAddresses;

/** The certificate data in DER format.
 */
@property (nonatomic, readonly) NSData *data;

/// The underlying `SecCertificate` reference.
@property (nonatomic, readonly) SecCertificateRef SecCertificate;

@end
