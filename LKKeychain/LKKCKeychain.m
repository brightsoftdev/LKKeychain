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

static CFMutableDictionaryRef keychains = NULL;

@interface LKKCKeychain()
@property (nonatomic, readonly) SecKeychainStatus status;
- (id)initWithSecKeychain:(SecKeychainRef)skeychain;
- (BOOL)getSettings:(SecKeychainSettings *)settings error:(NSError **)error;
- (NSArray *)findItemsWithClass:(CFTypeRef)itemClass query:(NSDictionary *)query error:(NSError **)error;
- (id)findItemWithClass:(CFTypeRef)itemClass query:(NSDictionary *)query error:(NSError **)error;
@end

@implementation LKKCKeychain
{
    SecKeychainRef _skeychain;
}

#pragma mark - Factory methods

+ (LKKCKeychain *)defaultKeychainWithError:(NSError **)error
{
    OSStatus status;
    SecKeychainRef skeychain = NULL;
    status = SecKeychainCopyDefault(&skeychain);
    if (status) {
        LKKCReportError(status, error, @"Can't get default keychain");
        return nil;
    }
    LKKCKeychain *keychain = [[LKKCKeychain alloc] initWithSecKeychain:skeychain];
    CFRelease(skeychain);
    return [keychain autorelease];
}

+ (LKKCKeychain *)keychainWithPath:(NSString *)path error:(NSError **)error
{
    OSStatus status;
    SecKeychainRef skeychain = NULL;
    status = SecKeychainOpen([path fileSystemRepresentation], &skeychain);
    if (status) {
        LKKCReportError(status, error, @"Can't open keychain at '%@'", path);
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

+ (LKKCKeychain *)createKeychainWithPath:(NSString *)path password:(NSString *)password error:(NSError **)error
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
        LKKCReportError(status, error, @"Can't create keychain at '%@", path);
        return nil;
    }
    LKKCKeychain *keychain = [[LKKCKeychain alloc] initWithSecKeychain:skeychain];
    CFRelease(skeychain);
    return [keychain autorelease];    
}

+ (NSArray *)keychainsInSearchListWithError:(NSError **)error
{
    OSStatus status;
    CFArrayRef searchList = NULL;
    status = SecKeychainCopySearchList(&searchList);
    if (status) {
        LKKCReportError(status, error, @"Can't get keychain search list");
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

#pragma mark - Lifecycle

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
                LKKCReportError(status, NULL, @"Can't get keychain path");
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
        LKKCReportError(status, NULL, @"Can't get keychain status");
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

- (BOOL)getSettings:(SecKeychainSettings *)settings error:(NSError **)error
{
    NSAssert(_skeychain, @"Keychain deleted");

    OSStatus status;
    settings->version = SEC_KEYCHAIN_SETTINGS_VERS1;
    status = SecKeychainCopySettings(_skeychain, settings);
    if (status) {
        LKKCReportError(status, error, @"Can't get keychain settings");
        return NO;
    }
    return YES;
}

- (BOOL)lockOnSleep
{
    SecKeychainSettings settings;
    if (![self getSettings:&settings error:NULL])
        return NO;
    return settings.lockOnSleep;
}

- (BOOL)setLockOnSleep:(BOOL)lockOnSleep error:(NSError **)error
{
    SecKeychainSettings settings;
    if (![self getSettings:&settings error:error])
        return NO;
    settings.lockOnSleep = lockOnSleep;
    OSStatus status = SecKeychainSetSettings(_skeychain, &settings);
    if (status) {
        LKKCReportError(status, error, @"Can't set lockOnSleep parameter");
        return NO;
    }
    return YES;
}

- (NSTimeInterval)lockInterval
{
    SecKeychainSettings settings;
    if (![self getSettings:&settings error:NULL])
        return -1;
    if (settings.useLockInterval)
        return (NSTimeInterval)settings.lockInterval;
    else
        return 0;
}

- (BOOL)setLockInterval:(NSTimeInterval)lockInterval error:(NSError **)error
{
    SecKeychainSettings settings;
    if (![self getSettings:&settings error:error])
        return NO;
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
        LKKCReportError(status, error, @"Can't set keychain settings");
        return NO;
    }
    return YES;
}

#pragma mark - Class operations

+ (BOOL)userInteractionEnabled
{
    Boolean state;
    OSStatus status = SecKeychainGetUserInteractionAllowed(&state);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get user interaction state");
        return NO;
    }
    return state;
}

+ (BOOL)setUserInteractionEnabled:(BOOL)enabled error:(NSError **)error
{
    OSStatus status = SecKeychainSetUserInteractionAllowed((Boolean)enabled);
    if (status) {
        LKKCReportError(status, error, NULL, @"Can't set user interaction state");
        return NO;
    }
    return YES;
}

#pragma mark - Keychain operations

- (BOOL)lockWithError:(NSError **)error
{
    NSAssert(_skeychain, @"Keychain deleted");
    OSStatus status = SecKeychainLock(_skeychain);
    if (status) {
        LKKCReportError(status, error, @"Can't lock keychain");
        return NO;
    }
    return YES;
}

- (BOOL)unlockWithPassword:(NSString *)password error:(NSError **)error
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
        LKKCReportError(status, error, @"Can't unlock keychain");
        return NO;
    }
    return YES;
}

- (BOOL)deleteKeychainWithError:(NSError **)error
{
    NSAssert(_skeychain, @"Keychain already deleted");
    OSStatus status = SecKeychainDelete(_skeychain);
    if (status) {
        LKKCReportError(status, error, @"Can't delete keychain");
        return NO;
    }
    CFRelease(_skeychain);
    _skeychain = NULL;
    return YES;
}

#pragma mark - Searching

- (NSArray *)findItemsWithClass:(CFTypeRef)itemClass query:(NSDictionary *)query error:(NSError **)error
{
    NSAssert(_skeychain, @"Keychain deleted");
    NSMutableDictionary *q;
    if (query != nil)
        q = [NSMutableDictionary dictionaryWithDictionary:query];
    else
        q = [NSMutableDictionary dictionary];
    [q setObject:itemClass forKey:kSecClass];
    [q setObject:[NSArray arrayWithObject:(id)_skeychain] forKey:kSecMatchSearchList];
    [q setObject:(id)kCFBooleanTrue forKey:kSecReturnRef];
    [q setObject:(id)kCFBooleanTrue forKey:kSecReturnAttributes];
    [q setObject:kSecMatchLimitAll forKey:kSecMatchLimit];

    NSArray *items = nil;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)q, (CFTypeRef *)&items);
    if (status) {
        if (status != errSecItemNotFound)
            LKKCReportError(status, error, @"Can't search keychain");
        return nil;
    }
    [items autorelease];
    
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:[items count]];
    for (NSDictionary *itemDict in items) {
        SecKeychainItemRef sitem = (SecKeychainItemRef)[itemDict objectForKey:(id)kSecValueRef];
        LKKCKeychainItem *item = [LKKCKeychainItem itemWithClass:itemClass SecKeychainItem:sitem attributes:itemDict error:error];
        if (item == nil) {
            return nil;
        }
        [result addObject:item];
    }
    return result;    
}

- (id)findItemWithClass:(CFTypeRef)itemClass query:(NSDictionary *)query error:(NSError **)error
{
    NSAssert(_skeychain, @"Keychain deleted");
    NSMutableDictionary *q = [NSMutableDictionary dictionaryWithDictionary:query];
    [q setObject:itemClass forKey:kSecClass];
    [q setObject:(id)_skeychain forKey:kSecMatchSearchList];
    [q setObject:(id)kCFBooleanTrue forKey:kSecReturnRef];
    [q setObject:(id)kCFBooleanTrue forKey:kSecReturnAttributes];
    [q setObject:kSecMatchLimitOne forKey:kSecMatchLimit];
    
    NSDictionary *itemDict = nil;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)q, (CFTypeRef *)&itemDict);
    if (status) {
        if (status != errSecItemNotFound)
            LKKCReportError(status, error, @"Can't search keychain");
        return nil;
    }
    
    SecKeychainItemRef sitem = (SecKeychainItemRef)[itemDict objectForKey:(id)kSecValueRef];
    LKKCKeychainItem *item = [LKKCKeychainItem itemWithClass:itemClass SecKeychainItem:sitem attributes:itemDict error:error];
    [itemDict release];
    return item;
}

#pragma mark - Generic Passwords

- (NSArray *)genericPasswords
{
    return [self findItemsWithClass:kSecClassGenericPassword query:nil error:NULL];
}

- (LKKCGenericPassword *)genericPasswordWithPersistentID:(NSData *)persistentID
{
    return [self findItemWithClass:kSecClassGenericPassword 
                             query:[NSDictionary dictionaryWithObject:[NSArray arrayWithObject:persistentID]
                                                               forKey:kSecMatchItemList]
                             error:NULL];
}

- (LKKCGenericPassword *)genericPasswordWithService:(NSString *)service account:(NSString *)account
{
    return [self findItemWithClass:kSecClassGenericPassword
                             query:[NSDictionary dictionaryWithObjectsAndKeys:
                                    service, kSecAttrService,
                                    account, kSecAttrAccount,
                                    nil]
                             error:NULL];
}

#pragma mark - Internet passwords

- (NSArray *)internetPasswords
{
    return [self findItemsWithClass:kSecClassInternetPassword query:nil error:NULL];
}

- (LKKCInternetPassword *)internetPasswordWithPersistentID:(NSData *)persistentID
{
    return [self findItemWithClass:kSecClassInternetPassword 
                             query:[NSDictionary dictionaryWithObject:[NSArray arrayWithObject:persistentID]
                                                               forKey:kSecMatchItemList]
                             error:NULL];
}

- (NSArray *)internetPasswordsForServer:(NSString *)server
{
    return [self findItemsWithClass:kSecClassInternetPassword 
                              query:[NSDictionary dictionaryWithObject:server forKey:kSecAttrServer]
                              error:NULL];
}

#pragma mark - Certificates

- (NSArray *)certificates
{
    return [self findItemsWithClass:kSecClassCertificate query:nil error:NULL];
}

- (LKKCCertificate *)certificateWithPersistentID:(NSData *)persistentID
{
    return [self findItemWithClass:kSecClassCertificate
                             query:[NSDictionary dictionaryWithObject:[NSArray arrayWithObject:persistentID]
                                                               forKey:kSecMatchItemList]
                             error:NULL];
}

- (NSArray *)certificatesWithSubject:(NSData *)subject
{
    return [self findItemsWithClass:kSecClassCertificate
                              query:[NSDictionary dictionaryWithObject:subject forKey:kSecAttrSubject]
                              error:NULL];
}

- (NSArray *)certificatesWithPublicKeyHash:(NSData *)publicKeyHash
{
    return [self findItemsWithClass:kSecClassCertificate
                              query:[NSDictionary dictionaryWithObject:publicKeyHash forKey:kSecAttrPublicKeyHash]
                              error:NULL];
}

- (NSArray *)certificatesWithLabel:(NSString *)label
{
    return [self findItemsWithClass:kSecClassCertificate
                              query:[NSDictionary dictionaryWithObject:label forKey:kSecAttrLabel]
                              error:NULL];
}

#pragma mark - Identities

- (NSArray *)identities
{
    return [self findItemsWithClass:kSecClassIdentity query:nil error:NULL];
}

#pragma mark - Keys

- (NSArray *)publicKeys
{
    return [self findItemsWithClass:kSecClassKey 
                              query:[NSDictionary dictionaryWithObject:kSecAttrKeyClassPublic 
                                                                forKey:kSecAttrKeyClass]
                              error:NULL];
}

- (NSArray *)privateKeys
{
    return [self findItemsWithClass:kSecClassKey 
                              query:[NSDictionary dictionaryWithObject:kSecAttrKeyClassPrivate 
                                                                forKey:kSecAttrKeyClass]
                              error:NULL];
}

- (NSArray *)symmetricKeys
{
    return [self findItemsWithClass:kSecClassKey 
                              query:[NSDictionary dictionaryWithObject:kSecAttrKeyClassSymmetric
                                                                forKey:kSecAttrKeyClass]
                              error:NULL];
}

- (LKKCKey *)keyWithPersistentID:(NSData *)persistentID
{
    return [self findItemWithClass:kSecClassKey
                             query:[NSDictionary dictionaryWithObject:[NSArray arrayWithObject:persistentID]
                                                               forKey:kSecMatchItemList]
                             error:NULL];
}

- (NSArray *)publicKeysWithLabel:(NSString *)label
{
    return [self findItemsWithClass:kSecClassKey 
                              query:[NSDictionary dictionaryWithObjectsAndKeys:
                                     label, kSecAttrLabel,
                                     kSecAttrKeyClassPublic, kSecAttrKeyClass,
                                     nil]
                              error:NULL];
}

- (NSArray *)privateKeysWithLabel:(NSString *)label
{
    return [self findItemsWithClass:kSecClassKey 
                              query:[NSDictionary dictionaryWithObjectsAndKeys:
                                     label, kSecAttrLabel,
                                     kSecAttrKeyClassPrivate, kSecAttrKeyClass,
                                     nil]
                              error:NULL];
}

- (NSArray *)symmetricKeysWithLabel:(NSString *)label
{
    return [self findItemsWithClass:kSecClassKey 
                              query:[NSDictionary dictionaryWithObjectsAndKeys:
                                     label, kSecAttrLabel,
                                     kSecAttrKeyClassSymmetric, kSecAttrKeyClass,
                                     nil]
                              error:NULL];
}

@end
