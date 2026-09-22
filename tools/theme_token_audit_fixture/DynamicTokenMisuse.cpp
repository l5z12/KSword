// regression sample for theme_token_audit; not compiled.
//
// Each Bad* case is derived from a real fixed defect, while each Ok* represents a correct usage that must be allowed.
// The line containing the violation is marked with KSWORD_AUDIT_EXPECT; --self-test compares the set of reported line numbers
// against the set of marked line numbers to ensure they match exactly. Any discrepancy (extra or missing lines) counts as a failure.

void badRichTextSpan()
{
    // HardwareDock: CPU details cell as-is.
    // Note: The inline style's padding-right:18px; includes a semicolon. Statement delimiters must skip string literals;
    // otherwise, the statement would be truncated before the HTML tag, and this violation would go undetected.
    const QString kHtml = QStringLiteral(
        "<td style=\"padding-right:18px;vertical-align:top;\">"
        "<span style=\"color:%1;font-size:13px;\">%2</span></td>")
        .arg(ksword_theme::textSecondaryHex())  // KSWORD_AUDIT_EXPECT
        .arg(labelText.toHtmlEscaped());
}

void badQColorConstruct()
{
    // NotificationCardManager as-is.
    return QColor(ksword_theme::kPrimaryBlueHex);  // KSWORD_AUDIT_EXPECT
}

void badQColorName()
{
    // PluginHost remains unchanged.
    const QString kValue = QColor(ksword_theme::textPrimaryHex()).name();  // KSWORD_AUDIT_EXPECT
}

void badEnvironmentHandoff()
{
    // Cross-process parameter passing: the plugin process does not have this process's stylesheet.
    environment.insert(
        QStringLiteral("KSWORD_PLUGIN_COLOR_SURFACE"),
        ksword_theme::surfaceHex());  // KSWORD_AUDIT_EXPECT
}

void badPaintPath()
{
    // Rendering path: QTextCharFormat does not parse stylesheet functions.
    selection.format.setForeground(ksword_theme::onAccentDynamicHex());  // KSWORD_AUDIT_EXPECT
}

void okStyleSheet()
{
    // Normal stylesheet usage; dynamic roles exist precisely for this purpose and must be allowed.
    label->setStyleSheet(
        QStringLiteral("color:%1;background:%2;border:1px solid %3;")
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::borderHex()));
}

void okStaticTokenInRichText()
{
    // Rich text with a static token; this is the corrected form after the fix and must be allowed.
    const QString kHtml = QStringLiteral("<span style=\"color:%1;\">%2</span>")
        .arg(ksword_theme::textSecondaryColorHex())
        .arg(bodyText.toHtmlEscaped());
}
