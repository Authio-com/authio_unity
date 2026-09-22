#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <stdlib.h>
#import <string.h>

extern "C" {

static NSString *AuthioKeychainService(void) {
    return @"com.authio.unity";
}

const char *AuthioKeychain_Get(const char *key) {
    if (key == NULL) return NULL;
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: AuthioKeychainService(),
        (__bridge id)kSecAttrAccount: [NSString stringWithUTF8String:key],
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };
    CFTypeRef data = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &data);
    if (status != errSecSuccess || data == NULL) return NULL;
    NSData *bytes = (__bridge_transfer NSData *)data;
    NSString *text = [[NSString alloc] initWithData:bytes encoding:NSUTF8StringEncoding];
    if (text == nil) return NULL;
    return strdup([text UTF8String]);
}

void AuthioKeychain_Set(const char *key, const char *value) {
    if (key == NULL) return;
    NSDictionary *match = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: AuthioKeychainService(),
        (__bridge id)kSecAttrAccount: [NSString stringWithUTF8String:key]
    };
    SecItemDelete((__bridge CFDictionaryRef)match);
    if (value == NULL) return;
    NSData *bytes = [[NSString stringWithUTF8String:value] dataUsingEncoding:NSUTF8StringEncoding];
    if (bytes == nil) return;
    NSDictionary *add = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: AuthioKeychainService(),
        (__bridge id)kSecAttrAccount: [NSString stringWithUTF8String:key],
        (__bridge id)kSecValueData: bytes,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    };
    SecItemAdd((__bridge CFDictionaryRef)add, NULL);
}

void AuthioKeychain_Free(const char *ptr) {
    if (ptr != NULL) free((void *)ptr);
}

}
