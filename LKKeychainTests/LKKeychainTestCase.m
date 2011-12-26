//
//  LKKeychainTestCase.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-15.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKeychainTestCase.h"

@implementation LKKeychainTestCase

- (void)setUp
{
    [super setUp];
    _keychain = [[self createTestKeychain:@"Test"] retain];
}

- (void)tearDown
{
    [_keychain release];
    _keychain = nil;
    [super tearDown];
}

- (LKKCKeychain *)createTestKeychain:(NSString *)name
{
    NSError *error = nil;
    BOOL result;

    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:[name stringByAppendingPathExtension:@"keychain"]];
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        LKKCKeychain *oldkeychain = [LKKCKeychain keychainWithPath:path error:&error];
        if (oldkeychain != nil) {
            result = [oldkeychain deleteKeychainWithError:&error];
            if (!result)
                return nil;
        }
    }
    LKKCKeychain *keychain = [[LKKCKeychain createKeychainWithPath:path password:@"foobar" error:&error] retain];
    return keychain;
}

- (NSData *)dataFromResource:(NSString *)resource ofType:(NSString *)extension
{
    NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:resource ofType:extension];
    should(path != nil);
    if (path == nil)
        return nil;
    
    NSData *data = [NSData dataWithContentsOfFile:path];
    should(data != nil);
    if (data == nil)
        return nil;
    
    return data;
}

- (LKKCCertificate *)certificateFromResourceName:(NSString *)name
{
    NSData *DERData = [self dataFromResource:name ofType:@"cer"];
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

- (NSArray *)allTestCertificates
{
    return [NSArray arrayWithObjects:
            [self validCA],
            [self expiredCA],
            [self intermediateCA],
            [self validCert],
            [self expiredCert],
            [self validCertWithExpiredCA],
            [self validCertWithIntermediateCA],
            [self expiredCertWithIntermediateCA],
            nil];
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

@end
