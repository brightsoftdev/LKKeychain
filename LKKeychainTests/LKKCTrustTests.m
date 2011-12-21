//
//  LKKCTrustTests.m
//  LKKeychain
//
//  Created by Károly Lőrentey on 2011-12-21.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCTrustTests.h"

@implementation LKKCTrustTests

#pragma mark - Corrupt Certificate

- (void)testCorruptCert
{
    NSError *error = nil;
    LKKCCertificate *validCA = [self validCA];
    LKKCCertificate *corruptCert = [self corruptCert];
    
    NSArray *chain = [NSArray arrayWithObjects:corruptCert, validCA, nil];
    
    LKKCTrust *trust = [LKKCTrust trustForSSLServerCertificateChain:chain hostname:@"example.com"];
    trust.anchors = [NSArray arrayWithObject:validCA];
    
    // When the certificate is corrupt, we get a fatal trust failure.
    LKKCTrustResult result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultFatalTrustFailure, @"");    
    STAssertNil(trust.certificateChain, @"");
}

#pragma mark - Valid Certificate from Root CA

- (void)testValidSSLServerCertWithMissingCA
{
    NSError *error = nil;
    LKKCCertificate *validCert = [self validCert];
    NSArray *chain = [NSArray arrayWithObjects:validCert, nil]; // No CA
    
    LKKCTrust *trust = [LKKCTrust trustForSSLServerCertificateChain:chain hostname:@"example.com"];
    
    // When the certificate has a CA that we can't find, we should get a recoverable trust failure.
    // The result chain should have a single entry, the certificate that was verified.
    LKKCTrustResult result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultRecoverableTrustFailure, @"");
    STAssertEquals([trust.certificateChain count], 1u, @"");
}

- (void)testValidSSLServerCertWithUnknownCA
{
    NSError *error = nil;
    LKKCCertificate *validCA = [self validCA];
    LKKCCertificate *validCert = [self validCert];
    NSArray *chain = [NSArray arrayWithObjects:validCert, validCA, nil];
    
    LKKCTrust *trust = [LKKCTrust trustForSSLServerCertificateChain:chain hostname:@"example.com"];
    
    // When the chain is complete and valid, but the root CA is not a trusted anchor,
    // we should get a recoverable trust failure.
    // The result chain should have two entries (cert and its issuer).
    LKKCTrustResult result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultRecoverableTrustFailure, @"");
    STAssertEquals([trust.certificateChain count], 2u, @"");
}

- (void)testValidSSLServerCert
{
    NSError *error = nil;
    LKKCCertificate *validCA = [self validCA];
    LKKCCertificate *validCert = [self validCert];
    NSArray *chain = [NSArray arrayWithObjects:validCert, validCA, nil];
    
    LKKCTrust *trust = [LKKCTrust trustForSSLServerCertificateChain:chain hostname:@"example.com"];
    trust.anchors = [NSArray arrayWithObject:validCA];
    
    // A valid chain with a trusted root CA results in an Unspecified trust result,
    // since the user did not explicitly make a trust setting for any of the certs on this chain.
    // The result chain should have two entries (cert and its issuer).
    LKKCTrustResult result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultUnspecified, @"");
    STAssertEquals([trust.certificateChain count], 2u, @"");
    
    // Changing the verify date to when the cert wasn't yet valid should result in a recoverable trust failure.
    trust.verifyDate = [self notYetValidDate];
    result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultRecoverableTrustFailure, @"");
    STAssertEquals([trust.certificateChain count], 2u, @"");
    
    // The cert should check out with the Basic X.509 policy.
    LKKCTrust *trust2 = [LKKCTrust trustForBasicX509CertificateChain:chain];
    trust2.anchors = [NSArray arrayWithObject:validCA];
    result = [trust2 evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultUnspecified, @"");    
    STAssertEquals([trust2.certificateChain count], 2u, @"");    
}

- (void)testValidSSLServerCertWithCANotInCertificateChain
{
    NSError *error = nil;
    LKKCCertificate *validCA = [self validCA];
    LKKCCertificate *validCert = [self validCert];
    NSArray *chain = [NSArray arrayWithObjects:validCert, nil]; // No CA
    
    LKKCTrust *trust = [LKKCTrust trustForSSLServerCertificateChain:chain hostname:@"example.com"];
    trust.anchors = [NSArray arrayWithObject:validCA];
    
    // A valid chain with a trusted root CA results in an Unspecified trust result,
    // even if the CA isn't listed on the chain.
    // The result chain should have two entries (cert and its issuer).
    LKKCTrustResult result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultUnspecified, @"");
    STAssertEquals([trust.certificateChain count], 2u, @"");
}

- (void)testValidSSLServerCertWithBadHostname
{
    NSError *error = nil;
    LKKCCertificate *validCA = [self validCA];
    LKKCCertificate *validCert = [self validCert];
    NSArray *chain = [NSArray arrayWithObjects:validCert, validCA, nil];
    
    LKKCTrust *trust = [LKKCTrust trustForSSLServerCertificateChain:chain hostname:@"not-example.com"];
    trust.anchors = [NSArray arrayWithObject:validCA];
    
    // This is a valid chain with a trusted root CA, but the policy verification will fail 
    // due to the hostname mismatch.
    // The result chain should have two entries (cert and its issuer).
    LKKCTrustResult result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultRecoverableTrustFailure, @"");    
    STAssertEquals([trust.certificateChain count], 2u, @"");
    
    // The cert should check out with the Basic X.509 policy.
    LKKCTrust *trust2 = [LKKCTrust trustForBasicX509CertificateChain:chain];
    trust2.anchors = [NSArray arrayWithObject:validCA];
    result = [trust2 evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultUnspecified, @"");    
    STAssertEquals([trust2.certificateChain count], 2u, @"");    
}

- (void)testValidCertWithBadPolicy
{
    NSError *error = nil;
    LKKCCertificate *validCA = [self validCA];
    LKKCCertificate *validCert = [self validCert];
    NSArray *chain = [NSArray arrayWithObjects:validCert, validCA, nil];
    
    LKKCTrust *trust = [LKKCTrust trustForSSLClientCertificateChain:chain hostname:@"example.com"];
    trust.anchors = [NSArray arrayWithObject:validCA];
    
    // This is a valid chain with a trusted root CA, but the policy verification will fail 
    // because validCA is an SSL server certificate.
    // The result chain should have two entries (cert and its issuer).
    LKKCTrustResult result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultRecoverableTrustFailure, @"");        
    STAssertEquals([trust.certificateChain count], 2u, @"");

    // The cert should check out with the Basic X.509 policy.
    LKKCTrust *trust2 = [LKKCTrust trustForBasicX509CertificateChain:chain];
    trust2.anchors = [NSArray arrayWithObject:validCA];
    result = [trust2 evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultUnspecified, @"");    
    STAssertEquals([trust2.certificateChain count], 2u, @"");    
}

#pragma mark - Valid Certificate from Intermediate CA

- (void)testValidSSLServerCertWithIntermediateCA
{
    NSError *error = nil;
    LKKCCertificate *validCA = [self validCA];
    LKKCCertificate *intermediateCA = [self intermediateCA];
    LKKCCertificate *validCert = [self validCertWithIntermediateCA];

    NSArray *chain = [NSArray arrayWithObjects:validCert, intermediateCA, validCA, nil];
    
    LKKCTrust *trust = [LKKCTrust trustForSSLServerCertificateChain:chain hostname:@"example.com"];
    trust.anchors = [NSArray arrayWithObject:validCA];
    
    // We supplied a complete and valid chain with a trusted root CA, so the trust result is Unspecified.
    // The result chain should have three entries (cert, its issuer (the intermediate CA), and the root CA).
    LKKCTrustResult result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultUnspecified, @"");        
    STAssertEquals([trust.certificateChain count], 3u, @"");
    
    // Changing the verify date to when the cert wasn't yet valid should result in a recoverable trust failure.
    trust.verifyDate = [self notYetValidDate];
    result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultRecoverableTrustFailure, @"");
    STAssertEquals([trust.certificateChain count], 3u, @"");
}

- (void)testValidSSLServerCertWithIntermediateCAOnKeychain
{
    NSError *error = nil;
    LKKCCertificate *validCA = [self validCA];
    LKKCCertificate *intermediateCA = [self intermediateCA];
    LKKCCertificate *validCert = [self validCertWithIntermediateCA];
    
    BOOL res = [intermediateCA addToKeychain:_keychain error:&error];
    STAssertTrue(res, @"%@", [error localizedDescription]);
    
    NSArray *chain = [NSArray arrayWithObjects:validCert, nil]; // No CAs!
    
    LKKCTrust *trust = [LKKCTrust trustForSSLServerCertificateChain:chain hostname:@"example.com"];
    trust.anchors = [NSArray arrayWithObject:validCA];
    
    // The cert is valid, the intermediate CA is found on the keychain, and the root CA is trusted.
    // The result chain should have three entries (cert, its issuer (the intermediate CA), and the root CA).
    LKKCTrustResult result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultUnspecified, @"");            
    STAssertEquals([trust.certificateChain count], 3u, @"");
    
    // Changing the verify date to when the cert wasn't yet valid should result in a recoverable trust failure.
    trust.verifyDate = [self notYetValidDate];
    result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultRecoverableTrustFailure, @"");
    STAssertEquals([trust.certificateChain count], 3u, @"");
}

- (void)testValidSSLServerCertWithMissingIntermediateCA
{
    NSError *error = nil;
    LKKCCertificate *validCA = [self validCA];
    LKKCCertificate *validCert = [self validCertWithIntermediateCA];
    
    NSArray *chain = [NSArray arrayWithObjects:validCert, nil]; // No CAs!
    
    LKKCTrust *trust = [LKKCTrust trustForSSLServerCertificateChain:chain hostname:@"example.com"];
    trust.anchors = [NSArray arrayWithObject:validCA];
    
    // When the intermediate CA is missing, the chain cannot be evaluated.
    // The result chain should have a single entry (the cert itself).
    LKKCTrustResult result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultRecoverableTrustFailure, @"");
    STAssertEquals([trust.certificateChain count], 1u, @"");
}

#pragma mark - Expired Certificate from Root CA

- (void)testExpiredCertificate
{
    NSError *error = nil;
    LKKCCertificate *validCA = [self validCA];
    LKKCCertificate *expiredCert = [self expiredCert];
    
    NSArray *chain = [NSArray arrayWithObjects:expiredCert, validCA, nil];
    
    LKKCTrust *trust = [LKKCTrust trustForSSLServerCertificateChain:chain hostname:@"example.com"];
    trust.anchors = [NSArray arrayWithObject:validCA];
    
    // If the certificate has expired, we get a recoverable trust failure.
    // The result chain should have two entries (cert + CA).
    LKKCTrustResult result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultRecoverableTrustFailure, @"");
    STAssertEquals([trust.certificateChain count], 2u, @"");    
    
    // Changing the verify date to when the cert was valid should result in a Unspecified trust result.
    trust.verifyDate = [self validDateForExpiredCerts];
    result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultUnspecified, @"");
    STAssertEquals([trust.certificateChain count], 2u, @"");    
}

#pragma mark - Expired Certificate from Intermediate CA

- (void)testExpiredCertificateWithIntermediateCA
{
    NSError *error = nil;
    LKKCCertificate *validCA = [self validCA];
    LKKCCertificate *intermediateCA = [self intermediateCA];
    LKKCCertificate *expiredCert = [self expiredCertWithIntermediateCA];
    
    NSArray *chain = [NSArray arrayWithObjects:expiredCert, intermediateCA, validCA, nil];
    
    LKKCTrust *trust = [LKKCTrust trustForSSLServerCertificateChain:chain hostname:@"example.com"];
    trust.anchors = [NSArray arrayWithObject:validCA];
    
    // If the certificate has expired, we get a recoverable trust failure.
    // The result chain should have three entries (cert, intermediate CA and root CA).
    LKKCTrustResult result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultRecoverableTrustFailure, @"");
    STAssertEquals([trust.certificateChain count], 3u, @"");    
    
    // Changing the verify date to when the cert was valid should result in a Unspecified trust result.
    trust.verifyDate = [self validDateForExpiredCerts];
    result = [trust evaluateWithError:&error];
    STAssertEquals(result, LKKCTrustResultUnspecified, @"");
    STAssertEquals([trust.certificateChain count], 3u, @"");        
}

@end
