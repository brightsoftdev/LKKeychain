//
//  LKKCKeychain.m
//  LKKCKeychain
//
//  Created by Karoly Lorentey on 2011-10-22.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeychain.h"
#import "LKKCKeychainItem.h"
#import "LKKCUtil.h"

@interface LKKCKeychain()
- (SecKeychainSettings)settings;
@end

static CFMutableDictionaryRef keychains = NULL;

@implementation LKKCKeychain
{
    SecKeychainRef _skeychain;
}

- (id)initWithSecKeychain:(SecKeychainRef)skeychain
{
    self = [super init];
    if (self == nil)
        return nil;
    
    if (keychains == NULL) {
        keychains = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
    }
    
    if (CFDictionaryContainsKey(keychains, skeychain)) {
        LKKCKeychain *canonicalKeychain = CFDictionaryGetValue(keychains, skeychain);
        [self release];
        NSAssert(canonicalKeychain->_skeychain == skeychain, @"internal");
        return [canonicalKeychain retain];
    }

    CFDictionarySetValue(keychains, skeychain, self);
    CFRetain(skeychain);
    _skeychain = skeychain;
    return self;
}

- (void)dealloc
{
    NSAssert(CFDictionaryContainsKey(keychains, _skeychain), @"");
    CFDictionaryRemoveValue(keychains, _skeychain);
    CFRelease(_skeychain);
    _skeychain = NULL;
    [super dealloc];
}

- (NSString *)description
{
    if (_skeychain == NULL)
        return [NSString stringWithFormat:@"<LKKCKeychain %p (deleted)>", self];

    SecKeychainStatus skeychainStatus = self.status;
    NSString *statusString = @"";
    if (skeychainStatus & kSecUnlockStateStatus)
        statusString = [statusString stringByAppendingString:@", unlocked"];
    if (skeychainStatus & kSecReadPermStatus)
        statusString = [statusString stringByAppendingString:@", readable"];
    if (skeychainStatus & kSecWritePermStatus)
        statusString = [statusString stringByAppendingString:@", writable"];
    
    return [NSString stringWithFormat:@"<LKKCKeychain %p at '%@'%@>", self, self.path, statusString];
}

#pragma mark - Factory methods

+ (LKKCKeychain *)defaultKeychain
{
    OSStatus status;
    SecKeychainRef skeychain = NULL;
    status = SecKeychainCopyDefault(&skeychain);
    if (status) {
        LKKCReportError(status, @"Can't get default keychain");
        return nil;
    }
    LKKCKeychain *keychain = [[LKKCKeychain alloc] initWithSecKeychain:skeychain];
    CFRelease(skeychain);
    return [keychain autorelease];
}

+ (LKKCKeychain *)keychainWithPath:(NSString *)path
{
    OSStatus status;
    SecKeychainRef skeychain = NULL;
    status = SecKeychainOpen([path fileSystemRepresentation], &skeychain);
    if (status) {
        LKKCReportError(status, @"Can't open keychain at '%@'", path);
        return nil;
    }
    LKKCKeychain *keychain = [[LKKCKeychain alloc] initWithSecKeychain:skeychain];
    CFRelease(skeychain);
    return [keychain autorelease];    
}

+ (LKKCKeychain *)keychainWithSecKeychain:(SecKeychainRef)skeychain
{
    return [[[LKKCKeychain alloc] initWithSecKeychain:skeychain] autorelease];
}

+ (LKKCKeychain *)createKeychainWithPath:(NSString *)path password:(NSString *)password
{
    OSStatus status;
    SecKeychainRef skeychain = NULL;
    if (password != nil) {
        status = SecKeychainCreate([path fileSystemRepresentation], (UInt32)[password length], [password UTF8String], NO, NULL, &skeychain);
    }
    else {
        status = SecKeychainCreate([path fileSystemRepresentation], 0, NULL, YES, NULL, &skeychain);
    }
    if (status) {
        LKKCReportError(status, @"Can't create keychain at '%@", path);
        return nil;
    }
    LKKCKeychain *keychain = [[LKKCKeychain alloc] initWithSecKeychain:skeychain];
    CFRelease(skeychain);
    return [keychain autorelease];    
}

+ (NSArray *)keychainsInSearchList 
{
    OSStatus status;
    CFArrayRef searchList = NULL;
    status = SecKeychainCopySearchList(&searchList);
    if (status) {
        LKKCReportError(status, @"Can't get keychain search list");
        return nil;
    }
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:CFArrayGetCount(searchList)];
    CFIndex count = CFArrayGetCount(searchList);
    for (CFIndex i = 0; i < count; i++) {
        SecKeychainRef skeychain = (SecKeychainRef)CFArrayGetValueAtIndex(searchList, i);
        [result addObject:[[[LKKCKeychain alloc] initWithSecKeychain:skeychain] autorelease]];
    }
    return result;
}

#pragma mark - Keychain properties

- (SecKeychainRef)SecKeychain
{
    return _skeychain;
}

- (NSString *)path
{
    NSAssert(_skeychain, @"Keychain deleted");

    OSStatus status;
    UInt32 pathsize = MAXPATHLEN;
    while (YES) {
        char path[pathsize];
        status = SecKeychainGetPath(_skeychain, &pathsize, path);
        if (status) {
            if (status == errSecBufferTooSmall) {
                LKKCReportError(status, @"Can't get keychain path");
                return nil;
            }
            pathsize *= 2;
            continue;
        }
        else {
            return [NSString stringWithCString:path encoding:NSUTF8StringEncoding];
        }
    }
}

- (SecKeychainStatus)status
{
    NSAssert(_skeychain, @"Keychain deleted");

    SecKeychainStatus skeychainStatus = 0;
    OSStatus status = SecKeychainGetStatus(_skeychain, &skeychainStatus);
    if (status) {
        LKKCReportError(status, @"Can't get keychain status");
        return 0;
    }
    return skeychainStatus;
}

- (BOOL)isLocked
{
    return (self.status & kSecUnlockStateStatus) == 0;
}

- (BOOL)isReadable
{
    return (self.status & kSecReadPermStatus) != 0;
}

- (BOOL)isWritable
{
    return (self.status & kSecWritePermStatus) != 0;
}

- (SecKeychainSettings)settings
{
    NSAssert(_skeychain, @"Keychain deleted");

    OSStatus status;
    SecKeychainSettings settings = { .version =  SEC_KEYCHAIN_SETTINGS_VERS1 };
    status = SecKeychainCopySettings(_skeychain, &settings);
    if (status) {
        LKKCReportError(status, @"Can't get keychain settings");
    }
    return settings;
}

- (BOOL)lockOnSleep
{
    SecKeychainSettings settings = [self settings];
    return settings.lockOnSleep;
}

- (void)setLockOnSleep:(BOOL)lockOnSleep
{
    SecKeychainSettings settings = [self settings];
    settings.lockOnSleep = lockOnSleep;
    OSStatus status = SecKeychainSetSettings(_skeychain, &settings);
    if (status) {
        LKKCReportError(status, @"Can't set keychain settings");
    }
}

- (NSTimeInterval)lockInterval
{
    SecKeychainSettings settings = [self settings];
    if (settings.useLockInterval)
        return (NSTimeInterval)settings.lockInterval;
    else
        return 0;
}

- (void)setLockInterval:(NSTimeInterval)lockInterval
{
    SecKeychainSettings settings = [self settings];
    if (lockInterval > 0) {
        settings.useLockInterval = YES;
        settings.lockInterval = (UInt32)lockInterval;
    }
    else {
        settings.useLockInterval = NO;
        settings.lockInterval = INT_MAX;
    }
    OSStatus status = SecKeychainSetSettings(_skeychain, &settings);
    if (status) {
        LKKCReportError(status, @"Can't set keychain settings");
    }
}

#pragma mark - Class operations

+ (BOOL)userInteractionEnabled
{
    Boolean state;
    OSStatus status = SecKeychainGetUserInteractionAllowed(&state);
    if (status) {
        LKKCReportError(status, @"Can't get user interaction state");
        return NO;
    }
    return state;
}

+ (void)setUserInteractionEnabled:(BOOL)enabled
{
    OSStatus status = SecKeychainSetUserInteractionAllowed((Boolean)enabled);
    if (status) {
        LKKCReportError(status, @"Can't set user interaction state");
    }
}

#pragma mark - Keychain operations

- (BOOL)lock
{
    NSAssert(_skeychain, @"Keychain deleted");
    OSStatus status = SecKeychainLock(_skeychain);
    if (status) {
        LKKCReportError(status, @"Can't lock keychain");
        return NO;
    }
    return YES;
}

- (BOOL)unlockWithPassword:(NSString *)password;
{
    NSAssert(_skeychain, @"Keychain deleted");
    OSStatus status;
    if (password != nil) {
        status = SecKeychainUnlock(_skeychain, (UInt32)[password length], [password UTF8String], YES);
    }
    else {
        status = SecKeychainUnlock(_skeychain, 0, NULL, NO);
    }
    if (status) {
        LKKCReportError(status, @"Can't unlock keychain");
        return NO;
    }
    return YES;
}

- (BOOL)deleteKeychain
{
    NSAssert(_skeychain, @"Keychain already deleted");
    OSStatus status = SecKeychainDelete(_skeychain);
    if (status) {
        LKKCReportError(status, @"Can't delete keychain");
        return NO;
    }
    CFRelease(_skeychain);
    _skeychain = NULL;
    return YES;
}

#pragma mark - Searching

- (NSArray *)findItemsWithClass:(CFTypeRef)itemClass keyClass:(CFTypeRef)keyClass
{
    NSAssert(_skeychain, @"Keychain deleted");
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                  itemClass, kSecClass, 
                                  [NSArray arrayWithObject:(id)_skeychain], kSecMatchSearchList,
                                  kCFBooleanTrue, kSecReturnRef,
                                  kCFBooleanTrue, kSecReturnAttributes,
                                  kSecMatchLimitAll, kSecMatchLimit,
                                  nil];
    if (keyClass) {
        [query setObject:keyClass forKey:kSecAttrKeyClass];
    }
    NSArray *items = nil;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&items);
    if (status) {
        if (status != errSecItemNotFound)
            LKKCReportError(status, @"Can't search keychain");
        return nil;
    }
    
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:[items count]];
    for (NSDictionary *itemDict in items) {
        SecKeychainItemRef sitem = (SecKeychainItemRef)[itemDict objectForKey:(id)kSecValueRef];
        LKKCKeychainItem *item = [LKKCKeychainItem itemWithClass:itemClass SecKeychainItem:sitem attributes:itemDict];
        [result addObject:item];
    }
    [items release];
    return result;    
}

- (NSArray *)internetPasswords
{
    return [self findItemsWithClass:kSecClassInternetPassword keyClass:NULL];
}

- (NSArray *)genericPasswords
{
    return [self findItemsWithClass:kSecClassGenericPassword keyClass:NULL];
}

- (NSArray *)certificates
{
    return [self findItemsWithClass:kSecClassCertificate keyClass:NULL];
}

- (NSArray *)publicKeys
{
    return [self findItemsWithClass:kSecClassKey keyClass:kSecAttrKeyClassPublic];
}

- (NSArray *)privateKeys
{
    return [self findItemsWithClass:kSecClassKey keyClass:kSecAttrKeyClassPrivate];
}

- (NSArray *)identities
{
    return [self findItemsWithClass:kSecClassIdentity keyClass:NULL];
}

- (NSArray *)symmetricKeys
{
    return [self findItemsWithClass:kSecClassKey keyClass:kSecAttrKeyClassSymmetric];
}

@end
