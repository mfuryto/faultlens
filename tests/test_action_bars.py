"""Actual colored toolbar layout stays aligned and usable at SSH widths."""
import asyncio
import unittest
from textual.widgets import Button
from faultlens.textual_app import FaultlensApp,FirewallDialog,ActionBar
from faultlens.firewall_state import collect
from tests.firewall_state_fixtures import Runner,START


class ActionBarTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):asyncio.get_running_loop().slow_callback_duration=2

    async def test_wide_rows_compact_wrapping_and_selected_window_are_explicit(self):
        report=collect(Runner(),window='period',since_us=START,until_us=START+1000000)
        async def collector(**options):return report
        app=FaultlensApp(initial_collect=False,firewall_collector=collector)
        async with app.run_test(size=(140,36)) as pilot:
            await pilot.pause(.01);app.push_screen(FirewallDialog());dialog=app.screen
            async with asyncio.timeout(4):
                while dialog.report is None:await pilot.pause(.01)
            await pilot.pause(.02)
            for ids in (('boot','hour','day','period'),('rules','chains','sets','jails','bans','sources','records','original','evidence')):
                buttons=[dialog.query_one('#firewall-'+key,Button) for key in ids]
                self.assertEqual(1,len({button.region.y for button in buttons}))
                self.assertTrue(all(button.styles.background.a>0 for button in buttons))
                self.assertEqual(len(buttons),len({button.region.x for button in buttons}))
            self.assertEqual('primary',dialog.query_one('#firewall-day',Button).variant)
            await pilot.resize_terminal(40,12);await pilot.pause(.02)
            self.assertTrue(any(bar.styles.height.value>1 for bar in dialog.query(ActionBar)))
            for bar in dialog.query(ActionBar):
                buttons=list(bar.query(Button))
                self.assertEqual(len(buttons),len({(b.region.x,b.region.y) for b in buttons}))
            await pilot.resize_terminal(140,36);await pilot.click('#firewall-hour')
            async with asyncio.timeout(4):
                while dialog.report is None:await pilot.pause(.01)
            self.assertEqual('primary',dialog.query_one('#firewall-hour',Button).variant)
