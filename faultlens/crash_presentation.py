"""Explain retained crash fragments without decoding, collection or boot attribution."""
from .presentation import size

LIMITS=[
    'Fragments are not attributed to the selected boot, an event time or a root cause.',
    'A panic signature is Possible evidence only; authenticity is unverified. Fragments are not reassembled.',
    'Duplicate content hashes are not independent corroboration or incident counts.',
    'Empty, unavailable or unmatched evidence does not exclude a crash. Existing source and analysis limits still apply.',
]
SOURCE_REASONS={
    'access_denied':'Existing access did not permit this source read. No elevation or permission change was attempted.',
    'source_absent_or_changed':'The source was absent or changed during collection; this does not establish that crash recording is disabled.',
    'unsafe_unsupported_or_incomplete_snapshot':'The snapshot was unsafe, unsupported or incomplete; no successful record prefix was retained.',
}
ANALYSIS_REASONS={
    'non_utf8_content':'The fragment is not valid UTF-8; supported text signatures were not analyzed. Original bytes remain encoded losslessly.',
    'binary_nul_content':'The fragment contains NUL bytes; supported text signatures were not analyzed. Original bytes remain encoded losslessly.',
    'text_analysis_structure_limit':'The text exceeds a signature-analysis structure limit. Retained content remains available without a complete signature assessment.',
}


def source_view(source):
    if source['state']!='available':
        observed='Crash-evidence source unavailable'
        meaning=[SOURCE_REASONS.get(source.get('reason'),'The source did not provide a usable snapshot; absence of a crash is not established.')]
    else:
        observed=str(len(source['records']))+' retained crash fragments'
        if not source['records']:
            meaning=['No supported records were visible in this snapshot. This does not exclude a crash or records retained elsewhere.']
        else:
            matched=sum(bool(record['panic_signature_lines']) for record in source['records'])
            meaning=[str(matched)+' fragments contain supported panic signatures (Possible). This is not a number of independent crashes.']
            if source['analysis_state'] in {'partial','unavailable'}:
                meaning.append('Some or all retained content could not be analyzed for supported text signatures. Collection availability is not analysis completeness.')
    if source.get('excluded_entries'):
        meaning.append(str(source['excluded_entries'])+' entries were excluded by source policy; their content was not read.')
    return {'Observed':observed,'Source':source['source'],'Source root':source.get('source_root','Fixed source; see technical details'),
            'What it means':meaning,'What you can do':[
                'Inspect fragment content, encoding and source metadata locally before relating it to journal or recording evidence.',
                'Do not delete records, mount filesystems, change archive policy or attribute a boot from these observations alone.'],
            'Evidence limits':list(LIMITS),'Technical details':source}


def record_label(record):
    return ('Fragment '+str(record['record_index'])+' | '+size(record['bytes_examined'])+' | '
            +('Possible panic signature' if record['panic_signature_lines'] else 'No supported signature established'))


def record_view(record):
    meaning=[]
    if record['analysis_state']!='available':
        meaning.append(ANALYSIS_REASONS.get(record.get('analysis_reason'),'Supported text-signature analysis was unavailable; no absence of a panic is inferred.'))
    elif record['panic_signature_lines']:
        meaning.append('Supported panic text matched at the retained line references. It does not verify the fragment, its time, boot identity or cause.')
    else:
        meaning.append('No supported panic text matched this fragment. Split, unsupported or missing evidence can conceal a signature.')
    if record['content']['encoding']=='base64':
        meaning.append('Content is preserved in base64. This can represent binary bytes or bound JSON expansion; encoding alone does not determine whether text analysis succeeded.')
    return {'Observed':record_label(record),'Relative path':record.get('relative_path'),
            'Confidence':record['confidence'],'What it means':meaning,
            'Signature line references':record['panic_signature_lines'],'Original content':record['content'],
            'What you can do':['Review the unchanged technical metadata and full encoded content locally; do not treat timestamps, path names or matching hashes as boot attribution.'],
            'Evidence limits':list(LIMITS),'Technical details':record}
