#include <gtest/gtest.h>

#include <iostream>
#include <chrono>

#define private public
#include "ip/cidr.h"
#include "ip/ip_with_country.h"

namespace lego {

namespace ip {

namespace test {

class TestCidr : public testing::Test {
public:
    static void SetUpTestCase() {
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

private:

};

TEST_F(TestCidr, All) {
    Cidr cidr;
    ASSERT_EQ(cidr.Init("./geolite.conf"), kIpSuccess);
    ASSERT_EQ(cidr.GetGeoId("134.209.178.180"), 2635167);
    ASSERT_EQ(cidr.GetGeoId("134.209.184.49"), 2635167);
    ASSERT_EQ(cidr.GetGeoId("167.71.113.28"), 6252001);
    ASSERT_EQ(cidr.GetGeoId("167.71.170.154"), 6252001);
    ASSERT_EQ(cidr.GetGeoId("167.71.172.135"), 6252001);
    ASSERT_EQ(cidr.GetGeoId("167.71.232.241"), 1269750);
    ASSERT_EQ(cidr.GetGeoId("167.71.232.145"), 1269750);
    ASSERT_EQ(cidr.GetGeoId("167.71.232.29"), 1269750);
    ASSERT_EQ(cidr.GetGeoId("178.128.22.31"), 1880251);

    ASSERT_EQ(ip::IpWithCountry::Instance()->Init("./geolite.conf", "./geo_country.conf"), kIpSuccess);
    ASSERT_EQ(ip::IpWithCountry::Instance()->GetCountryCode("134.209.178.180"), "GB");
    ASSERT_EQ(ip::IpWithCountry::Instance()->GetCountryCode("134.209.184.49"), "GB");
    ASSERT_EQ(ip::IpWithCountry::Instance()->GetCountryCode("167.71.113.28"), "US");
    ASSERT_EQ(ip::IpWithCountry::Instance()->GetCountryCode("167.71.170.154"), "US");
    ASSERT_EQ(ip::IpWithCountry::Instance()->GetCountryCode("167.71.172.135"), "US");
    ASSERT_EQ(ip::IpWithCountry::Instance()->GetCountryCode("167.71.232.241"), "IN");
    ASSERT_EQ(ip::IpWithCountry::Instance()->GetCountryCode("167.71.232.145"), "IN");
    ASSERT_EQ(ip::IpWithCountry::Instance()->GetCountryCode("167.71.232.29"), "IN");
    ASSERT_EQ(ip::IpWithCountry::Instance()->GetCountryCode("178.128.22.31"), "SG");
}

}  // namespace test

}  // namespace ip

}  // namespace lego
