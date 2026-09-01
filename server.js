app.get(
  '/api/ads',
  async (req, res) => {
    try {

      console.log('==============================');
      console.log('PRODUCT ADS - CONSULTANDO');
      console.log('==============================');

      const advertiser =
        await getAdvertiser();

      console.log(
        'ADVERTISER:',
        JSON.stringify(advertiser, null, 2)
      );

      const site =
        advertiser.site_id ||
        'MLA';

      const advertiserId =
        advertiser.advertiser_id;

      if (!advertiserId) {
        throw new Error(
          'Mercado Libre no devolvió advertiser_id.'
        );
      }

      const date =
        req.query.date ||
        todayArgentina();

      const params =
        new URLSearchParams();

      params.set(
        'limit',
        '50'
      );

      params.set(
        'offset',
        '0'
      );

      params.set(
        'date_from',
        date
      );

      params.set(
        'date_to',
        date
      );

      params.set(
        'metrics',
        [
          'clicks',
          'prints',
          'ctr',
          'cost',
          'cpc',
          'acos',
          'organic_units_quantity',
          'organic_units_amount',
          'organic_items_quantity',
          'direct_items_quantity',
          'indirect_items_quantity',
          'advertising_items_quantity',
          'cvr',
          'roas',
          'sov',
          'direct_units_quantity',
          'indirect_units_quantity',
          'units_quantity',
          'direct_amount',
          'indirect_amount',
          'total_amount'
        ].join(',')
      );

      params.set(
        'metrics_summary',
        'true'
      );

      const endpoint =
        `/advertising/${site}/advertisers/${advertiserId}/product_ads/campaigns/search?${params.toString()}`;

      console.log(
        'PRODUCT ADS ENDPOINT:',
        endpoint
      );

      const data =
        await mlAdsFetch(
          endpoint
        );

      console.log(
        'PRODUCT ADS RESPONSE:',
        JSON.stringify(
          data,
          null,
          2
        )
      );

      const campaigns =
        Array.isArray(
          data.results
        )
          ? data.results
          : [];

      const summary =
        data.metrics_summary ||
        {};

      // --------------------------------------------------------
      // SUMA ROBUSTA
      // --------------------------------------------------------

      let cost = Number(
        summary.cost
      ) || 0;

      let totalAmount = Number(
        summary.total_amount
      ) || 0;

      let clicks = Number(
        summary.clicks
      ) || 0;

      let prints = Number(
        summary.prints
      ) || 0;

      let units = Number(
        summary.units_quantity
      ) || 0;

      let directAmount = Number(
        summary.direct_amount
      ) || 0;

      let indirectAmount = Number(
        summary.indirect_amount
      ) || 0;

      let directUnits = Number(
        summary.direct_units_quantity
      ) || 0;

      let indirectUnits = Number(
        summary.indirect_units_quantity
      ) || 0;

      // --------------------------------------------------------
      // SI METRICS_SUMMARY VIENE VACÍO,
      // SUMAMOS LAS CAMPAÑAS
      // --------------------------------------------------------

      if (
        !cost &&
        campaigns.length
      ) {

        console.log(
          'metrics_summary vacío. Sumando campañas...'
        );

        cost = 0;
        totalAmount = 0;
        clicks = 0;
        prints = 0;
        units = 0;
        directAmount = 0;
        indirectAmount = 0;
        directUnits = 0;
        indirectUnits = 0;

        for (
          const campaign
          of campaigns
        ) {

          const metrics =
            campaign.metrics ||
            campaign;

          cost +=
            Number(
              metrics.cost
            ) || 0;

          totalAmount +=
            Number(
              metrics.total_amount
            ) || 0;

          clicks +=
            Number(
              metrics.clicks
            ) || 0;

          prints +=
            Number(
              metrics.prints
            ) || 0;

          units +=
            Number(
              metrics.units_quantity
            ) || 0;

          directAmount +=
            Number(
              metrics.direct_amount
            ) || 0;

          indirectAmount +=
            Number(
              metrics.indirect_amount
            ) || 0;

          directUnits +=
            Number(
              metrics.direct_units_quantity
            ) || 0;

          indirectUnits +=
            Number(
              metrics.indirect_units_quantity
            ) || 0;

        }

      }

      // --------------------------------------------------------
      // CALCULOS
      // --------------------------------------------------------

      const ctr =
        prints > 0
          ? (
              clicks /
              prints
            ) * 100
          : 0;

      const cpc =
        clicks > 0
          ? cost /
            clicks
          : 0;

      const acos =
        totalAmount > 0
          ? (
              cost /
              totalAmount
            ) * 100
          : 0;

      const roas =
        cost > 0
          ? totalAmount /
            cost
          : 0;

      const result = {

        clicks,

        prints,

        cost,

        total_amount:
          totalAmount,

        direct_amount:
          directAmount,

        indirect_amount:
          indirectAmount,

        units_quantity:
          units,

        direct_units_quantity:
          directUnits,

        indirect_units_quantity:
          indirectUnits,

        ctr,

        cpc,

        acos,

        roas

      };

      console.log(
        '=============================='
      );

      console.log(
        'PUBLICIDAD CALCULADA:',
        JSON.stringify(
          result,
          null,
          2
        )
      );

      console.log(
        '=============================='
      );

      res.json({

        ok: true,

        date_from:
          date,

        date_to:
          date,

        advertiser: {

          id:
            advertiserId,

          siteId:
            site,

          name:
            advertiser.advertiser_name ||
            advertiser.name ||
            null

        },

        summary:
          result,

        campaigns,

        fetch_error:
          null

      });

    } catch (error) {

      console.error(
        '=============================='
      );

      console.error(
        'PRODUCT ADS ERROR'
      );

      console.error(
        error.message
      );

      console.error(
        error.details ||
        ''
      );

      console.error(
        '=============================='
      );

      res.status(200).json({

        ok: false,

        error:
          error.message,

        details:
          error.details ||
          null,

        summary:
          emptyAdsSummary(),

        campaigns: []

      });

    }

  }
);
