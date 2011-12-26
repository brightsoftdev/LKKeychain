//
//  LKKCCertificate.h
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

@class LKKCKey;

/** Represents a digital certificate. */
@interface LKKCCertificate : LKKCKeychainItem

+ (LKKCCertificate *)certificateWithDERData:(NSData *)data;
+ (LKKCCertificate *)certificateWithSecCertificate:(SecCertificateRef)scertificate;

@property (nonatomic, readonly) LKKCKey *publicKey;

/** --------------------------------------------------------------------------------
 @name Certificate Attributes
 -------------------------------------------------------------------------------- */

/** The human-readable name of this certificate. Shows up as "Name" in Keychain Access.
 
 The value is nil if this certificate is not on a keychain.

 This property corresponds to the `kSecAttrLabel` attribute.
 */
@property (nonatomic, retain) NSString *label;

/** The normalized subject DN of this certificate, in DER format, including the outer SEQUENCE tag.

 This property has a valid value even if the certificate is not on a keychain.
 
 This property corresponds to the `kSecAttrSubject` attribute.
 */
@property (nonatomic, readonly) NSData *subject;

/** The normalized issuer DN of this certificate, in DER format, including the outer SEQUENCE tag.
 
 This property has a valid value even if the certificate is not on a keychain.
 
 This property corresponds to the `kSecAttrIssuer` attribute, and it is part of the
 primary key for certificate items, along with <certificateType> and <serialNumber>.
 */
@property (nonatomic, readonly) NSData *issuer;

/** The serial number of this certificate.
 
 This property has a valid value even if the certificate is not on a keychain.
 
 This property corresponds to the `kSecAttrSerialNumber` attribute, and it is part of the 
 primary key for certificate items, along with <certificateType> and <issuer>.
 */
@property (nonatomic, readonly) NSData *serialNumber;

/** The SHA-1 hash of the DER representation of this certificate's public key.
 
 If the certificate is not on a keychain, the value of this property is calculated on the fly.
 
 This property corresponds to the `kSecAttrPublicKeyHash` attribute.
 */
@property (nonatomic, readonly) NSData *publicKeyHash;

/** The subject key identifier of this certificate, if present.
 
 The subject key identifier is an optional certificate extension that allows quickly identifying
 certificates that contain a particular public key. Its value may be derived from the public
 key itself (using a possibly truncated SHA-1 digest), or it may contain a unique value.
 
 The value is nil if this certificate is not on a keychain.
 
 This property corresponds to the `kSecAttrSubjectKeyID` attribute.
 */
@property (nonatomic, readonly) NSData *subjectKeyID;

/** The type of this certificate, encoded as a CSSM_CERT_TYPE value.
 
 The value is nil if this certificate is not on a keychain.
 
 This property corresponds to the `kSecAttrCertificateType` attribute, and it is part of the 
 primary key for certificate items, along with <issuer> and <serialNumber>.
 */
@property (nonatomic, readonly) UInt32 certificateType;

/** The encoding of this certificate, encoded as a CSSM_CERT_ENCODING value.
 
 The value is nil if this certificate is not on a keychain.
 
 This property corresponds to the `kSecAttrCertificateEncoding` attribute.
 */
@property (nonatomic, readonly) UInt32 certificateEncoding;

/** --------------------------------------------------------------------------------
 @name Miscellaneous Properties
 -------------------------------------------------------------------------------- */

/** The Common Name of the certificate subject.
 */
@property (nonatomic, readonly) NSString *commonName;

/** Human-readable summary of the certificate subject.
 */
@property (nonatomic, readonly) NSString *subjectSummary;

/** Email addresses included in the certificate subject.
 */
@property (nonatomic, readonly) NSArray *emailAddresses;

/** The certificate data in DER format.
 */
@property (nonatomic, readonly) NSData *data;

/** The certificate data in dictionary format, as returned by `SecCertificateCopyValues`.
 */
- (NSDictionary *)contents;

/** The underlying `SecCertificate` reference.
 */
@property (nonatomic, readonly) SecCertificateRef SecCertificate;

@end
