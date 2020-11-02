/*************************************************************************
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
***************************************************************************/

#include <string>
#include <cstdlib>
#include <iostream>

#include "regxstring.h"

using namespace std;

static string trim(std::string str){
    size_t i = 0,e = str.length();
    for(;i < e && std::isspace(str[i]);++i);
    size_t j = e;
    for(;j > i && std::isspace(str[j - 1]);--j);
    return (i < j ? str.substr(i,j - i) : "");
}

static string pre_handle(const string & str)
{
    string ret = trim(str);
    if(!ret.empty()) {
        if(ret[0] != '^') {
            ret.insert(ret.begin(),'^');
        }

        if(ret[ret.size() - 1] != '$') {
            ret.push_back('$');
        }
    }
    return ret;
}

static void rand_init(void) {
    unsigned int seed;
    FILE* urandom = fopen("/dev/urandom", "r");
    size_t ret = fread(&seed, sizeof(int), 1, urandom);
    (void)ret;
    fclose(urandom);
    srand(seed);
    srandom(seed);
}

int main(int argc, const char ** argv)
{
    CRegxString regxstr;
    string regx = "";

    switch(argc) {
        case 2:
            rand_init();
            regx = argv[1];
            break;

        case 3:
            int pseudo_seed = 0;
            int i = 0;
            while(argv[1][i]) {
                pseudo_seed *= 10;
                pseudo_seed += argv[1][i] - '0';
                i++;
            }
            srand(pseudo_seed);
            srandom(pseudo_seed);
            regx = argv[2];
            break;
    }

    regxstr.ParseRegx(pre_handle(regx).c_str());
    cout << regxstr.RandString() << endl;
    
    return 0;
}
