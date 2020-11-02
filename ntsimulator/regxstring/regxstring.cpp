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

#include "regxstring_impl.h"
#include "regxstring.h"

CRegxString::CRegxString(const char * regx)
    : impl_(0)
{
    ParseRegx(regx);
}

CRegxString::~CRegxString()
{
    if(impl_)
        delete impl_;
}

void CRegxString::ParseRegx(const char * regx,const Config * config)
{
    if(!regx)
        return;
    if(!impl_)
        impl_ = new REGXSTRING_NS::__CRegxString;
    impl_->ParseRegx(regx,config);
}

const char * CRegxString::Regx() const
{
    return (impl_ ? impl_->Regx().c_str() : 0);
}

const char * CRegxString::RandString()
{
    return (impl_ ? impl_->RandString().c_str() : 0);
}
const char * CRegxString::LastString() const
{
    return (impl_ ? impl_->LastString().c_str() : 0);
}

void CRegxString::Debug(std::ostream & out) const
{
    if(impl_)
        impl_->Debug(out);
}
