import pygeoip


gip = pygeoip.GeoIP('db_geo/GeoLite2-Country.mmdb')

gip.country_code_by_name('wikipedia.org')