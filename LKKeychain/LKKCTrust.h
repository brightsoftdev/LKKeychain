//
//  LKKCTrust.h
//  LKKeychain
//
//  Created by Károly Lőrentey on 2011-12-18.
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

#import <Foundation/Foundation.h>
#import <LKKeychain/LKKCCertificate.h>

typedef enum LKKCTrustResult {
    LKKCTrustResultInvalid,
    LKKCTrustResultProceed,
    LKKCTrustResultConfirm,
    LKKCTrustResultDeny,
    LKKCTrustResultUnspecified,
    LKKCTrustResultRecoverableTrustFailure,
    LKKCTrustResultFatalTrustFailure,
    LKKCTrustResultOtherError
} LKKCTrustResult;

/** LKKCTrust verifies certificates and evaluates their trust settings.
 
 It supports verifying certificates under three policies: the basic X.509 policy, 
 and the SSL server and client policies.
 */
@interface LKKCTrust : NSObject {
@private
    SecTrustRef _strust;
    NSMutableArray *_anchors;
    BOOL _systemAnchors;
}

/** --------------------------------------------------------------------------------
 @name Creating Trust Instances
 -------------------------------------------------------------------------------- */

/** Returns a trust management object for verifying a certificate using the Basic X.509 policy.
 
 The certificate to verify must be the first item (at index 0) in the _certificateChain_ argument.
 The rest of the items are additional certificates that may be on the certificate chain.
 You should include all known certificates on the certificate chain, preferably in order.
 
 <evaluateWithError:> will search the keychain search list and the set of trusted anchors to find 
 any missing certificiates.
 
 @param certificateChain The certificate to verify along with additional certificates that may be of interest while evaluating trust.
 @return An LKKCTrust object for verifying the specified certificate.

 @see [LKKCTrust setKeychains:]
 @see [LKKCTrust anchors]
 @see [LKKCTrust evaluateWithError:]
*/
+ (LKKCTrust *)trustForBasicX509CertificateChain:(NSArray *)certificateChain;

/** Returns a trust management object for verifying a certificate using the SSL Server policy. 

 The certificate to verify must be the first item (at index 0) in the _certificateChain_ argument.
 The rest of the items are additional certificates that may be on the certificate chain.
 You should include all known certificates on the certificate chain, preferably in order.
 
 <evaluateWithError:> will search the keychain search list and the set of trusted anchors to find 
 any missing certificiates.
 
 @param certificateChain The certificate to verify along with additional certificates that may be of interest while evaluating trust.
 @param hostname The server hostname to match against the certificate.
 @return An LKKCTrust object for verifying the specified certificate.
 
 @see [LKKCTrust setKeychains:]
 @see [LKKCTrust anchors]
 @see [LKKCTrust evaluateWithError:]
 */
+ (LKKCTrust *)trustForSSLServerCertificateChain:(NSArray *)certificateChain hostname:(NSString *)hostname;

/** Returns a trust management object for verifying a certificate using the SSL Client policy. 
 
 The certificate to verify must be the first item (at index 0) in the _certificateChain_ argument.
 The rest of the items are additional certificates that may be on the certificate chain.
 You should include all known certificates on the certificate chain, preferably in order.
 
 <evaluateWithError:> will search the keychain search list and the set of trusted anchors to find 
 any missing certificiates.
 
 @param certificateChain The certificate to verify along with additional certificates that may be of interest while evaluating trust.
 @param hostname The client hostname to match against the certificate.
 @return An LKKCTrust object for verifying the specified certificate.
 
 @see [LKKCTrust setKeychains:]
 @see [LKKCTrust anchors]
 @see [LKKCTrust evaluateWithError:]
 */
+ (LKKCTrust *)trustForSSLClientCertificateChain:(NSArray *)certificateChain hostname:(NSString *)hostname;

/** --------------------------------------------------------------------------------
 @name Anchor Certificates
 -------------------------------------------------------------------------------- */

/** The set of anchor certificates to trust while evaluating the certificate.
 
 Setting this property to a non-nil value disables trusting the system-wide anchors.
 
 Setting this property to nil reverts to trusting the system-wide anchor certificates.
 
 If you want to edit the system-wide anchors, use <systemAnchors> to get them,
 copy and edit that list as you wish, then assign the result back to this property.

 If you simply want to specify additional root certificates to extend the system-wide list, see 
 <addCustomAnchors:>.
 
 The value of this property is the complete set of currently trusted anchors, 
 including system-wide anchors (if not previously disabled) and any anchors 
 added with <addCustomAnchors:>.
 
 @see [LKKCTrust systemAnchors]
 @see [LKKCTrust addCustomAnchors:]
 */
@property (nonatomic, copy) NSArray *anchors;

/** Extend the set of trusted anchor certificates.

 Adds the certificates in _anchors_ as trusted anchor certificates, without disabling any 
 previously trusted anchor.
 
 @param anchors A set of additional anchor certificates to trust while verifying the certificate.
 @see [LKKCTrust anchors]
 */
- (void)addCustomAnchors:(NSArray *)anchors;

/** The system-wide set of trusted anchor certificates.
 */
+ (NSArray *)systemAnchors;

/** --------------------------------------------------------------------------------
 @name Evaluation parameters
 -------------------------------------------------------------------------------- */

/** Set the list of keychains that will be searched for intermediate certificates.
 
 Use nil to search the default keychain search list. (This is the default.)
 
 To disable keychain searches, set the search list to an empty array.
 
 @param keychains A list of LKKCKeychain objects, or nil to search the default keychain search list.
 */
- (void)setKeychains:(NSArray *)keychains;

/** The time at which to verify the certificate.
 
 If this property is set to nil (which is the default), the certificate is evaluated using the current time.
 In this case, getting the value of this property finalizes the "current time" at which to verify the certificate.
 Thus, the value of this is never nil.
 */
@property (nonatomic, retain) NSDate *verifyDate;

/** --------------------------------------------------------------------------------
 @name Evaluating Trust
 -------------------------------------------------------------------------------- */

/** Evaluates trust by verifying signatures and checking trust settings.
 
 Each certificate on the certificate chain is checked according to the policy (X.509, SSL) 
 specified when creating this trust object. 
 
 If there is a user-specified trust setting for one or more certificates on the chain, the trust setting 
 that is closest to the leaf certificate determines the trust result (Proceed, Confirm, or Deny).
 If the result is Confirm, you should pop up a confirmation dialog to let the user decide whether to
 trust this certificate.
 
 If there is no user-specified trust setting for any certificates on the chain, the trust result 
 will be Unspecified. In this case, you should pop up a confirmation dialog (using `SFCertificateTrustPanel`),
 or use a default action (allow or deny).
 
 The following results are possible:
 
 - `LKKCTrustResultProceed` -- The user explicitly indicated to trust this certificate chain.
 - `LKKCTrustResultConfirm` -- Interactive confirmation is necessary before proceeding.
 - `LKKCTrustResultDeny` -- The user explicitly denied trust to this certificate chain.
 - `LKKCTrustResultUnspecified` -- The user did not specify a trust setting for this certificate chain. Proceed with the default action.
 - `LKKCTrustResultRecoverableTrustFailure` -- Trust denied with these settings, but may be allowed after changing parameters. (E.g., certificate has expired or is not yet valid.)
 - `LKKCTrustResultFatalTrustFailure` -- Trust denied; changing parameters won't help. (E.g., invalid signature.)
 - `LKKCTrustResultInvalid` -- Invalid input. The trust could not be evaluated.
 - `LKKCTrustResultOtherError` -- Internal error, trust could not be evaluated.
 
 @param error On output, the error that occurred in case trust could not be evaluated (optional).
 
 @return A trust result.
 */
- (LKKCTrustResult)evaluateWithError:(NSError **)error;

/** The full certificate chain for the evaluated certificate.
 
 The leaf certificate is at index 0 of the returned array; the item at the highest index is the 
 anchor certificate (or the last known intermediate certificate if the anchor could not be found).
 
 This property has a nil value if the trust has not been evaluated yet.
 */
@property (nonatomic, readonly) NSArray *certificateChain;

/** The public key of the evaluated certificate. */
@property (nonatomic, readonly) LKKCKey *publicKey;


/** --------------------------------------------------------------------------------
 @name Low-level Access
 -------------------------------------------------------------------------------- */
 
/** The underlying `SecTrust` reference. */
@property (nonatomic, readonly) SecTrustRef SecTrust;

@end
