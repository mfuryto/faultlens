"""Invented crash fragments only; no crash generation, mounts or live evidence reads."""
import copy
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.crash_presentation import source_view,record_view
from faultlens.pstore import analyze
from faultlens.tui_model import Session
from tests.test_incidents import JournalRunner,record


class CrashPresentationTests(unittest.TestCase):
    def test_signatures_and_duplicate_fragments_do_not_become_crash_counts_or_boot_attribution(self):
        source=analyze(lambda:([b'Kernel panic - not syncing: invented\n']*2,0))
        original=copy.deepcopy(source); view=source_view(source)
        self.assertIn('2 fragments contain',' '.join(view['What it means']))
        self.assertIn('not a number of independent crashes',' '.join(view['What it means']))
        value=record_view(source['records'][0])
        self.assertEqual('Possible',value['Confidence'])
        self.assertIs(source['records'][0]['content'],value['Original content'])
        self.assertIs(source['records'][0],value['Technical details'])
        self.assertIn('not attributed',' '.join(value['Evidence limits']))
        self.assertEqual(original,source)

    def test_binary_and_structure_limits_are_analysis_failures_not_missing_bytes(self):
        for content in (b'\xff',b'invented\x00',b'x'*4097):
            source=analyze(lambda:([content],0))
            value=record_view(source['records'][0])
            self.assertEqual('available',source['state'])
            self.assertEqual('unavailable',source['analysis_state'])
            self.assertEqual('Unknown',value['Confidence'])
            self.assertTrue(value['Original content']['value'])
            self.assertIn('could not be analyzed',' '.join(source_view(source)['What it means']))

    def test_base64_for_json_expansion_is_not_misclassified_as_failed_text_analysis(self):
        source=analyze(lambda:([b'\x01'*100],0))
        fragment=source['records'][0]
        self.assertEqual('base64',fragment['content']['encoding'])
        self.assertEqual('available',fragment['analysis_state'])
        value=record_view(fragment)
        self.assertIn('encoding alone does not determine',' '.join(value['What it means']))
        self.assertNotIn('were not analyzed',' '.join(value['What it means']))

    def test_empty_and_unavailable_sources_are_not_crash_exclusions(self):
        empty=source_view(analyze(lambda:([],0)))
        self.assertIn('does not exclude a crash',' '.join(empty['What it means']))
        for error in (PermissionError(),FileNotFoundError(),ValueError()):
            with patch('faultlens.pstore.collect',side_effect=error): source=analyze()
            view=source_view(source)
            self.assertEqual('Crash-evidence source unavailable',view['Observed'])
            self.assertEqual([],source['records'])
            self.assertIn('does not exclude a crash',' '.join(view['Evidence limits']))

    def test_cli_readable_details_and_json_keep_opt_in_originals(self):
        for flags in ([],['--details'],['--json']):
            output=io.StringIO()
            self.assertEqual(0,main(['diagnose','--pstore',*flags],runner=JournalRunner([record()]),stdout=output,
                pstore_collector=lambda:([b'Kernel panic - not syncing: invented\n'],0)))
            if not flags:
                self.assertIn('Live crash evidence',output.getvalue())
                self.assertIn('Possible panic signature',output.getvalue())
                self.assertNotIn('not syncing: invented',output.getvalue())
            elif flags==['--json']:
                fragment=json.loads(output.getvalue())['pstore']['records'][0]
                self.assertEqual('Kernel panic - not syncing: invented\n',fragment['content']['value'])
                self.assertNotIn('What it means',fragment)

    def test_tui_navigation_keeps_original_content_without_collection(self):
        session=Session(runner=JournalRunner([record()]),pstore_collector=lambda:([b'\xff'],0))
        session.choose_page(5); session.update_setting('pstore'); session.refresh()
        source=session.data['pstore']; original=copy.deepcopy(session.data)
        with patch.object(session,'refresh',side_effect=AssertionError('No hidden collection')):
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='crash_source')
            session.open_row()
            self.assertIs(source['records'],session.value['Retained fragments'])
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='crash_records')
            session.open_row(); session.open_row()
            self.assertIs(source['records'][0]['content'],session.value['Original content'])
            self.assertIs(source['records'][0],session.value['Technical details'])
            self.assertEqual('inspect',next(row.action for row in session.rows() if row.label=='Original content'))
        self.assertEqual(original,session.data)

    def test_raw_metadata_access_remains_raw(self):
        session=Session(runner=JournalRunner([record()]),pstore_collector=lambda:([b'invented'],0))
        session.choose_page(5); session.update_setting('pstore'); session.refresh()
        session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='crash_source')
        session.open_row(inspect_only=True)
        self.assertIs(session.data['pstore'],session.value)
        self.assertTrue(all(row.action=='inspect' for row in session.rows()))

    def test_live_and_archive_views_remain_separate_even_with_matching_content(self):
        fragment=b'Kernel panic - not syncing: invented\n'
        session=Session(runner=JournalRunner([record()]),pstore_collector=lambda:([fragment],0),
                        pstore_archive_collector=lambda:([fragment],0))
        session.choose_page(5); session.update_setting('pstore'); session.update_setting('pstore_archive'); session.refresh()
        self.assertEqual(session.data['pstore']['records'][0]['sha256'],session.data['pstore_archive']['records'][0]['sha256'])
        for key,expected in [('pstore','pstore-live'),('pstore_archive','systemd-pstore-archive')]:
            session.selected=next(i for i,row in enumerate(session.rows()) if row.value is session.data[key])
            session.open_row()
            self.assertEqual(expected,session.value['Source'])
            self.assertIs(session.data[key],session.value['Technical details'])
            self.assertIn('not independent corroboration',' '.join(session.value['Evidence limits']))
            session.back()


if __name__=='__main__':
    unittest.main()
