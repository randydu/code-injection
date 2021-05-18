#include "catch_ex.h"

#include "test_util.h"

REGISTER_TEST_CALLBACK([](bool start){
    if(start){
        printf("code-injection unit-test begins...\n");
        
        CI::ut::init();

    } else {
        printf("code-injection unit-test ends.\n");
    }
});
