//
//  LKKCCertificateTests.m
//  LKKeychain
//
//  Created by Károly Lőrentey on 2011-12-22.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import <CommonCrypto/CommonDigest.h>
#import "LKKCCertificateTests.h"

@implementation LKKCCertificateTests

- (void)testSubjectDNLookup
{
    NSError *error = nil;
    LKKCCertificate *certificate = [self validCert];
    LKKCCertificate *caCert = [self validCA];

    NSData *floatingSubject = certificate.subject;
    NSData *floatingIssuer = certificate.issuer;

    BOOL r = [certificate addToKeychain:_keychain error:&error];
    should(r);
    r = [caCert addToKeychain:_keychain error:&error];
    should(r);
    
    NSData *subject = certificate.subject;
    NSData *issuer = certificate.issuer;
    
    STAssertEqualObjects(floatingSubject, subject, @"The same cert should have the same normalized subject DN, whether or not it's on a keychain");
    STAssertEqualObjects(floatingIssuer, issuer, @"The same cert should have the same normalized issuer DN, whether or not it's on a keychain");

    NSArray *certsWithSubject = [_keychain certificatesWithSubject:subject];
    STAssertEquals([certsWithSubject count], 1u, @"Could not find certificate by its normalized subject DN");
    
    NSArray *certsWithIssuer = [_keychain certificatesWithSubject:issuer];
    STAssertEquals([certsWithIssuer count], 1u, @"Could not find CA certificate by its normalized subject DN");
}

- (NSData *)publicKeyHashForCertificate:(LKKCCertificate *)certificate
{
    // Calculate hash manually.
    NSError *error = nil;
    LKKCKey *publicKey = certificate.publicKey;
    should(publicKey != nil);
    NSData *publicKeyData = [publicKey keyDataWithError:&error];
    should(publicKeyData != nil);
    
    UInt8 md[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([publicKeyData bytes], [publicKeyData length], md);
    NSData *publicKeyHash = [NSData dataWithBytes:md length:CC_SHA1_DIGEST_LENGTH];
    return publicKeyHash;    
}

- (void)testPublicKeyHash
{
    NSError *error = nil;
    NSArray *certs = [self allTestCertificates];
    
    // Check hashes for standalone certificates.
    for (LKKCCertificate *certificate in certs) {
        shouldBeEqual(certificate.publicKeyHash, [self publicKeyHashForCertificate:certificate]);
    }
    
    // Check hashes for certificates on a keychain.
    for (LKKCCertificate *certificate in certs) {
        BOOL res = [certificate addToKeychain:_keychain error:&error];
        should(res);
    }
    
    for (LKKCCertificate *certificate in [_keychain certificates]) {
        shouldBeEqual(certificate.publicKeyHash, [self publicKeyHashForCertificate:certificate]);
    }
}


- (void)testValidCAValues
{
    LKKCCertificate *certificate = [self validCA];
    
    char *subject = "\x30\x4b\x31\x1b\x30\x19\x06\x03\x55\x04\x03\x0c\x12\x4c\x4b\x4b\x65\x79\x63\x68\x61\x69\x6e\x20\x54\x65\x73\x74\x20\x43\x41\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x48\x55\x31\x1f\x30\x1d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x10\x74\x65\x73\x74\x40\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d";
    char *hash = "\xf5\xe0\xbd\xff\x0e\x40\x81\xcb\xab\x43\x4c\x07\xfc\x13\x6f\x94\xec\x27\xfa\xf4";
    
    // Check property values for a standalone certificate.
    shouldBeEqual(certificate.data, [self dataFromResource:@"LKKeychain Test CA" ofType:@"cer"]);
    shouldBeEqual(certificate.subject, [NSData dataWithBytes:subject length:strlen(subject)]);
    shouldBeEqual(certificate.issuer, [NSData dataWithBytes:subject length:strlen(subject)]);
    shouldBeEqual(certificate.serialNumber, [NSData dataWithBytes:"\x01" length:1]);
    shouldBeEqual(certificate.publicKeyHash, [NSData dataWithBytes:hash length:20]);
    STAssertEquals(certificate.certificateType, (UInt32)0, @""); // Should be CSSM_CERT_X_509v1 when not standalone.
    STAssertEquals(certificate.certificateEncoding, (UInt32)0, @""); // Should be CSSM_CERT_ENCODING_DER when not standalone.
    shouldBeEqual(certificate.commonName, @"LKKeychain Test CA");
    shouldBeEqual(certificate.subjectSummary, @"LKKeychain Test CA");
    shouldBeEqual(certificate.subjectKeyID, nil);
    shouldBeEqual(certificate.emailAddresses, [NSArray arrayWithObject:@"test@example.com"]);
    
    NSError *error = nil;
    BOOL res = [certificate addToKeychain:_keychain error:&error];
    should(res);
    
    // Check property values for a certificate on a keychain.
    shouldBeEqual(certificate.data, [self dataFromResource:@"LKKeychain Test CA" ofType:@"cer"]);
    shouldBeEqual(certificate.subject, [NSData dataWithBytes:subject length:strlen(subject)]);
    shouldBeEqual(certificate.issuer, [NSData dataWithBytes:subject length:strlen(subject)]);
    shouldBeEqual(certificate.serialNumber, [NSData dataWithBytes:"\x01" length:1]);
    shouldBeEqual(certificate.publicKeyHash, [NSData dataWithBytes:hash length:20]);
    STAssertEquals(certificate.certificateType, (UInt32)CSSM_CERT_X_509v1, @"");
    STAssertEquals(certificate.certificateEncoding, (UInt32)CSSM_CERT_ENCODING_DER, @"");
    shouldBeEqual(certificate.commonName, @"LKKeychain Test CA");
    shouldBeEqual(certificate.subjectSummary, @"LKKeychain Test CA");
    shouldBeEqual(certificate.subjectKeyID, nil);
    shouldBeEqual(certificate.emailAddresses, [NSArray arrayWithObject:@"test@example.com"]);
}

- (void)testValidCertValues
{
    LKKCCertificate *certificate = [self validCert];
    
    char *subject = "\x30\x2b\x31\x1c\x30\x1a\x06\x03\x55\x04\x03\x0c\x13\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x20\x28\x56\x61\x6c\x69\x64\x29\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x48\x55";
    char *issuer = "\x30\x4b\x31\x1b\x30\x19\x06\x03\x55\x04\x03\x0c\x12\x4c\x4b\x4b\x65\x79\x63\x68\x61\x69\x6e\x20\x54\x65\x73\x74\x20\x43\x41\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x48\x55\x31\x1f\x30\x1d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x10\x74\x65\x73\x74\x40\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d";
    char *hash = "\xd6\x92\x14\xbe\x5c\x05\x94\x6b\xda\x15\xa0\xcf\x74\x8a\xc5\xde\x78\xd4\x77\x11";
    
    // Check property values for a standalone certificate.
    shouldBeEqual(certificate.data, [self dataFromResource:@"example.com (Valid)" ofType:@"cer"]);
    shouldBeEqual(certificate.subject, [NSData dataWithBytes:subject length:strlen(subject)]);
    shouldBeEqual(certificate.issuer, [NSData dataWithBytes:issuer length:strlen(issuer)]);
    shouldBeEqual(certificate.serialNumber, [NSData dataWithBytes:"\x02" length:1]);
    shouldBeEqual(certificate.publicKeyHash, [NSData dataWithBytes:hash length:20]);
    STAssertEquals(certificate.certificateType, (UInt32)0, @""); // Should be CSSM_CERT_X_509v1 when not standalone
    STAssertEquals(certificate.certificateEncoding, (UInt32)0, @""); // Should be CSSM_CERT_ENCODING_DER when not standalone
    shouldBeEqual(certificate.commonName, @"example.com (Valid)");
    shouldBeEqual(certificate.subjectSummary, @"example.com (Valid)");
    shouldBeEqual(certificate.subjectKeyID, nil);
    shouldBeEqual(certificate.emailAddresses, [NSArray array]);
    
    NSError *error = nil;
    BOOL res = [certificate addToKeychain:_keychain error:&error];
    should(res);
    
    // Check property values for a certificate on a keychain.
    shouldBeEqual(certificate.data, [self dataFromResource:@"example.com (Valid)" ofType:@"cer"]);
    shouldBeEqual(certificate.subject, [NSData dataWithBytes:subject length:strlen(subject)]);
    shouldBeEqual(certificate.issuer, [NSData dataWithBytes:issuer length:strlen(issuer)]);
    shouldBeEqual(certificate.serialNumber, [NSData dataWithBytes:"\x02" length:1]);
    shouldBeEqual(certificate.publicKeyHash, [NSData dataWithBytes:hash length:20]);
    STAssertEquals(certificate.certificateType, (UInt32)CSSM_CERT_X_509v1, @"");
    STAssertEquals(certificate.certificateEncoding, (UInt32)CSSM_CERT_ENCODING_DER, @"");
    shouldBeEqual(certificate.commonName, @"example.com (Valid)");
    shouldBeEqual(certificate.subjectSummary, @"example.com (Valid)");
    shouldBeEqual(certificate.subjectKeyID, nil);
    shouldBeEqual(certificate.emailAddresses, [NSArray array]);
}

@end
