//
//  LKKCTrustTests.m
//  LKKeychain
//
//  Created by Károly Lőrentey on 2011-12-21.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCTrustTests.h"

@implementation LKKCTrustTests

- (void)setUp
{
    _keychain = [[LKKeychainTestUtils createTestKeychain:@"Test"] retain];
}

- (void)tearDown
{
    [_keychain release];
    _keychain = nil;
}

- (LKKCCertificate *)certificateFromResourceName:(NSString *)name
{
    NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:name ofType:@"cer"];
    should(path != nil);
    if (path == nil)
        return nil;
    
    NSData *DERData = [NSData dataWithContentsOfFile:path];
    should(DERData != nil);
    if (DERData == nil)
        return nil;
    
    LKKCCertificate *certificate = [LKKCCertificate certificateWithDERData:DERData];
    return certificate;
}

- (LKKCCertificate *)validCA
{
    // This is a CA certificate that is valid until 2031.
    return [self certificateFromResourceName:@"LKKeychain Test CA"];
}

- (LKKCCertificate *)expiredCA
{
    // This is a CA certificate that expired at 2011-12-22 15:04 CET.
    // It was valid at 2011-12-22 00:00 CET.
    return [self certificateFromResourceName:@"LKKeychain Expired Test CA"];
}

- (LKKCCertificate *)intermediateCA
{
    // This is an intermediate CA signed by validCA, valid until 2031.
    return [self certificateFromResourceName:@"LKKeychain Intermediate CA"];
}

- (LKKCCertificate *)validCert
{
    // This is SSL server certificate for example.com, signed by validCA.
    // It is valid until 2031.
    return [self certificateFromResourceName:@"example.com (Valid)"];
}

- (LKKCCertificate *)expiredCert
{
    // This is SSL server certificate for example.com, signed by validCA.
    // It expired at 2011-12-22 15:19 CET. 
    // It was valid at 2011-12-22 00:00 CET.    
    return [self certificateFromResourceName:@"example.com (Expired)"];
}

- (LKKCCertificate *)corruptCert
{
    // This is a corrupt version of validCert whose signature is invalid.
    return [self certificateFromResourceName:@"example.com (Corrupt)"];    
}

- (LKKCCertificate *)validCertWithExpiredCA
{
    // This is an SSL server certificate for example.com, signed by expiredCA.
    // It is ostensibly valid until 2031, but its issuer has expired on 2011-12-22 15:04 CET.
    return [self certificateFromResourceName:@"example.com (Expired CA)"];
}

- (LKKCCertificate *)validCertWithIntermediateCA
{
    // This is an SSL server certificate for example.com, signed by intermediateCA.
    // It is valid until 2031.
    return [self certificateFromResourceName:@"example.com (Valid, Intermediate CA)"];
}

- (LKKCCertificate *)expiredCertWithIntermediateCA
{
    // This is an SSL server certificate for example.com, signed by intermediateCA.
    // The certificate has expired on 2011-12-22 15:21 CET.
    return [self certificateFromResourceName:@"example.com (Expired, Intermediate CA)"];
}

- (NSDateFormatter *)dateFormatter
{
    static NSDateFormatter *df = nil;
    if (df == nil) {
        df = [[NSDateFormatter alloc] init];
        NSLocale *locale = [[[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"] autorelease];
    
        [df setLocale:locale];
        [df setDateFormat:@"yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"];
        [df setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"CET"]];
    }
    return df;
}

- (NSDate *)notYetValidDate
{
    return [[self dateFormatter] dateFromString:@"2011-01-01T00:00:00Z"];
}

- (NSDate *)validDateForExpiredCerts
{
    return [[self dateFormatter] dateFromString:@"2011-12-22T00:00:00Z"];
}

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
