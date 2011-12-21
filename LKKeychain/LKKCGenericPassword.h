//
//  LKKCGenericPassword.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
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

/** `LKKCGenericPassword` represents a generic password in a keychain. 
 
 You can create a new generic password by calling  
 <[LKKCGenericPassword createPassword:service:account:]>. 
 It returns a floating password item that isn't on a keychain yet. 
 The password's attributes (such as its label and comment)
 are accessible as simple read-write properties. Once you've set up the attributes you want, call 
 <[LKKCKeychainItem addToKeychain:error:]> to add the item to a keychain.
 
     LKKCGenericPassword *password = [LKKCGenericPassword createPassword:@"secretPassword" 
                                                                 service:[[NSBundle mainBundle] bundleIdentifier]
                                                                 account:@"sample account"];
     password.label = [NSString stringWithFormat:@"%@ (%@)", password.service, password.account];
 
     LKKCKeychain *keychain = [LKKCKeychain defaultKeychain];
     BOOL result = [password addToKeychain:keychain error:NULL];
     if (!result) {
         // Oops
     }
 
 <LKKCKeychain> instances have methods for retrieving passwords stored on a particular keychain.
 
     LKKCKeychain *keychain = [LKKCKeychain defaultKeychain];
     LKKCGenericPassword *password = [keychain genericPasswordWithService:[[NSBundle mainBundle] bundleIdentifier] 
                                                                  account:@"sample account"];
     if (password != nil) {
         NSLog(@"Password: %@", password.password);
     }
 
 To modify an existing password, simply assign new values to its properties and save the changes 
 using <[LKKCKeychainItem saveItemWithError:]>.
 
     password.password = @"NewP4ssword";
     password.comment = @"This is a comment for the sample account password.";
 
     result = [password saveItemWithError:NULL];
     if (!result) {
         // Oops
     }
 
 To delete a password, call <[LKKCKeychainItem deleteItemWithError:]>.
 
     result = [password deleteItemWithError:NULL];
     if (!result) {
         // Oops
     }
*/
@interface LKKCGenericPassword : LKKCKeychainItem

/** --------------------------------------------------------------------------------
 @name Creating new passwords
 -------------------------------------------------------------------------------- */

/** Create a new generic password.
 
 You can use <[LKKCKeychainItem addToKeychain:error:]> to save the newly created password on a keychain.
 @param password The password value.
 @param service The value for the service attribute. For application-specific passwords, use your application's bundle id here.
 @param account The value for the account attribute. (A human-readable string of your choice.)
 */
+ (LKKCGenericPassword *)createPassword:(NSString *)password 
                                service:(NSString *)service
                                account:(NSString *)account;


/** --------------------------------------------------------------------------------
 @name Accessing the password value
 -------------------------------------------------------------------------------- */

/** The password value.
 
 The property getter returns nil when access was denied to this application.
 */
@property (nonatomic, retain) NSString *password;

/** Returns the password value.
 @param error On output, the error that occurred in case the password could not be accessed (optional).
 @return The password stored in this item, or nil when access was denied.
 */
- (NSString *)passwordWithError:(NSError **)error;

/** --------------------------------------------------------------------------------
 @name Item attributes
 -------------------------------------------------------------------------------- */

/** Service name. Shows up as "Where" in Keychain Access.
 
 For application-specific passwords, use the app's bundle ID for this field.
 
 This property corresponds to the `kSecAttrService` attribute.
 
 This property is part of the primary key for generic password items, along with <account>.
 Modifying it may invalidate previously generated persistent IDs that refer to this item.
 */
@property (nonatomic, retain) NSString *service;

/** Account name. Shows up as "Account" in Keychain Access.

 This property corresponds to the `kSecAttrAccount` attribute.

 This property is part of the primary key for generic password items, along with <service>.
 Modifying it may invalidate previously generated persistent IDs that refer to this item.
*/
@property (nonatomic, retain) NSString *account;

/** A human-readable label for this password. Shows up as "Name" in Keychain Access.
 
 This property corresponds to the `kSecAttrLabel` attribute.
 */
@property (nonatomic, retain) NSString *label;

/** The human-readable item kind ("Application Password" by default). Shows up as "Kind" in Keychain Access. 
 
 This property corresponds to the `kSecAttrDescription` attribute.
 */
@property (nonatomic, retain) NSString *kind;

/** Human-readable comment. Shows up as "Comments" in Keychain Access.
 
 This property corresponds to the `kSecAttrComment` attribute. 
 */
@property (nonatomic, retain) NSString *comment;

/** Creation date.
 
 This property corresponds to the `kSecAttrCreationDate` attribute.
 */
@property (nonatomic, readonly) NSDate *creationDate;

/** Last modification date. 
 
 This property corresponds to the `kSecAttrModificationDate` attribute.
 */
@property (nonatomic, readonly) NSDate *modificationDate;

/** If YES, the password value isn't displayed in Keychain Access. 
 
 This property corresponds to the `kSecAttrIsInvisible` attribute.
 */
@property (nonatomic, assign, getter = isInvisible) BOOL invisible;

/** If YES, this is a negative item without a password value.
 
 Negative items indicate that the user has explicitly disabled password storage for this account.
 
 This property corresponds to the `kSecAttrIsNegative` attribute. 
 */
@property (nonatomic, assign, getter = isNegative) BOOL negative;

/** Application-specific metadata. This data isn't displayed by Keychain Access. 
 
 This property corresponds to the `kSecAttrGeneric` attribute.
 */
@property (nonatomic, retain) NSData *appSpecificData;

@end

//kSecClassGenericPassword item attributes not represented above:
//kSecAttrAccess
//kSecAttrCreator
//kSecAttrType

