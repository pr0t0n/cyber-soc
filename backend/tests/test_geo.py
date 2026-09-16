import os

import pytest

from app.services import geo


@pytest.mark.skipif(not os.getenv("LIVE_GEO"), reason="LIVE_GEO não definido (chama ipinfo.io de verdade)")
async def test_live_geo_lookup_cloudflare_dns():
    res = await geo.query_geo("1.1.1.1")
    assert res is not None
    assert res["country"]
    assert isinstance(res["lat"], float)
