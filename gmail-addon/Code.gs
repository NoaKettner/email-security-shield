// ============================================================================
// EMAIL SECURITY SHIELD
// Gmail Add-on
// Automatic analysis + contextual actions
// ============================================================================


// ============================================================================
// 1. OPEN ADD-ON -> AUTOMATIC ANALYSIS
// ============================================================================

function onGmailMessageOpen(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

  const messageId = e.gmail.messageId;

  return analyzeMessage(messageId);
}


// ============================================================================
// 2. ANALYZE MESSAGE
// ============================================================================

function analyzeMessage(messageId) {

  const message = GmailApp.getMessageById(messageId);

  if (!message) {
    return buildErrorCard(
      "Email Not Found",
      "Could not access the selected email."
    );
  }


  // --------------------------------------------------------------------------
  // Extract email data
  // --------------------------------------------------------------------------

  const sender = parseSender(message.getFrom());
  const subject = message.getSubject();
  const body = message.getPlainBody();
  const htmlBody = message.getBody();

  const links = extractLinksFromHtml(htmlBody);

  // Used by backend scoring, but not displayed in UI
  const authentication =
    getAuthenticationResults(messageId);


  // --------------------------------------------------------------------------
  // Payload
  // --------------------------------------------------------------------------

  const emailJson = {
    sender: sender,
    subject: subject,
    body: body,
    links: links,
    authentication: authentication
  };


  console.log(
    "Sending to backend:\n" +
    JSON.stringify(emailJson, null, 2)
  );


  // --------------------------------------------------------------------------
  // Backend request
  // --------------------------------------------------------------------------

  const options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(emailJson),
    muteHttpExceptions: true
  };


  let response;

  try {

    response = UrlFetchApp.fetch(
      "https://pastor-condense-unequal.ngrok-free.dev/api/v1/analyze",
      options
    );

  } catch (error) {

    console.log(
      "Backend connection error: " +
      error
    );

    return buildErrorCard(
      "Connection Failed",
      "Could not connect to the analysis server."
    );
  }


  const statusCode =
    response.getResponseCode();

  const responseText =
    response.getContentText();


  if (statusCode !== 200) {

    console.log(
      "Backend error: " +
      responseText
    );

    return buildErrorCard(
      "Analysis Failed",
      "Backend returned HTTP " +
      statusCode
    );
  }


  let result;

  try {

    result = JSON.parse(
      responseText
    );

  } catch (error) {

    console.log(
      "Invalid JSON: " +
      responseText
    );

    return buildErrorCard(
      "Invalid Response",
      "The backend response could not be parsed."
    );
  }


  return buildResultCard(
    result,
    messageId
  );
}


// ============================================================================
// 3. RESULT CARD
// ============================================================================

function buildResultCard(
  result,
  messageId
) {

  result = result || {};


  const score =
    Math.max(
      0,
      Math.min(
        100,
        Number(result.score || 0)
      )
    );


  const signals =
    removeDuplicateSignals(
      result.signals || []
    );


  const ui =
    getUIConfig(score);


  const cardBuilder =
    CardService
      .newCardBuilder()

      .setHeader(
        CardService
          .newCardHeader()

          .setTitle(
            "Email Security Shield"
          )

          .setSubtitle(
            "Security Analysis Complete"
          )
      );


  // ==========================================================================
  // HERO
  // ==========================================================================

  const heroSection =
    CardService.newCardSection();


  heroSection.addWidget(

    CardService
      .newTextParagraph()

      .setText(
        "<center>" +

        "<font color=\"" +
        ui.color +
        "\">" +

        "<b>" +
        ui.verdict.toUpperCase() +
        "</b>" +

        "</font>" +

        "<br><br>" +

        "<font size=\"+2\">" +

        "<b>" +
        score +
        " / 100" +
        "</b>" +

        "</font>" +

        "<br><br>" +

        buildScoreDots(score) +

        "<br><br>" +

        "<font color=\"#5F6368\">" +
        ui.description +
        "</font>" +

        "</center>"
      )
  );


  cardBuilder.addSection(
    heroSection
  );


  // ==========================================================================
  // FINDINGS
  // ==========================================================================

  const findingsSection =
    CardService
      .newCardSection()

      .setHeader(
        signals.length > 0
          ? "Critical Signals"
          : "Security Check"
      );


  if (signals.length === 0) {

    findingsSection.addWidget(

      CardService
        .newTextParagraph()

        .setText(
          "✅ <b>No suspicious indicators detected</b><br>" +
          "The current checks did not identify a strong threat."
        )
    );

  } else {

    signals
      .slice(0, 5)

      .forEach(
        function(signal) {

          const normalized =
            normalizeSignal(signal);


          findingsSection.addWidget(

            CardService
              .newDecoratedText()

              .setText(
                "<b>" +
                getFindingEmoji(
                  normalized.code
                ) +
                " " +
                escapeHtml(
                  getFindingTitle(
                    normalized.code
                  )
                ) +
                "</b>"
              )

              .setBottomLabel(
                escapeHtml(
                  normalized.reason
                )
              )

              .setWrapText(true)
          );
        }
      );
  }


  cardBuilder.addSection(
    findingsSection
  );


  // ==========================================================================
  // RECOMMENDATION
  // ==========================================================================

  const recommendationSection =
    CardService
      .newCardSection()

      .setHeader(
        "Recommended Action"
      );


  recommendationSection.addWidget(

    CardService
      .newTextParagraph()

      .setText(
        "<b>" +
        ui.actionTitle +
        "</b>" +

        "<br>" +

        ui.actionText
      )
  );


  cardBuilder.addSection(
    recommendationSection
  );


  // ==========================================================================
  // CTA - ONLY MEDIUM / HIGH
  // ==========================================================================

  if (score >= 34) {

    const footer =
      CardService.newFixedFooter();


    // ------------------------------------------------------------------------
    // HIGH RISK
    // ------------------------------------------------------------------------

    if (score >= 67) {

      const deleteAction =
        CardService
          .newAction()

          .setFunctionName(
            "handleDeleteEmail"
          )

          .setParameters({
            messageId: messageId
          });


      const deleteButton =
        CardService
          .newTextButton()

          .setText(
            "DELETE EMAIL"
          )

          .setTextButtonStyle(
            CardService
              .TextButtonStyle
              .FILLED
          )

          .setBackgroundColor(
            "#D93025"
          )

          .setOnClickAction(
            deleteAction
          );


      const reportAction =
        CardService
          .newAction()

          .setFunctionName(
            "handleReportPhishing"
          )

          .setParameters({
            messageId: messageId
          });


      const reportButton =
        CardService
          .newTextButton()

          .setText(
            "REPORT PHISHING"
          )

          .setOnClickAction(
            reportAction
          );


      footer.setPrimaryButton(
        deleteButton
      );


      footer.setSecondaryButton(
        reportButton
      );
    }


    // ------------------------------------------------------------------------
    // MEDIUM / SUSPICIOUS
    // ------------------------------------------------------------------------

    else {

      const reportAction =
        CardService
          .newAction()

          .setFunctionName(
            "handleReportPhishing"
          )

          .setParameters({
            messageId: messageId
          });


      const reportButton =
        CardService
          .newTextButton()

          .setText(
            "REPORT PHISHING"
          )

          .setTextButtonStyle(
            CardService
              .TextButtonStyle
              .FILLED
          )

          .setBackgroundColor(
            "#F29900"
          )

          .setOnClickAction(
            reportAction
          );


      footer.setPrimaryButton(
        reportButton
      );
    }


    cardBuilder.setFixedFooter(
      footer
    );
  }


  return cardBuilder.build();
}


// ============================================================================
// 4. UI CONFIG
// ============================================================================

function getUIConfig(score) {

  // HIGH
  if (score >= 67) {

    return {

      verdict:
        "High Risk",

      color:
        "#D93025",

      description:
        "Strong malicious indicators were detected.",

      actionTitle:
        "Do not interact with this email",

      actionText:
        "Avoid clicking links, downloading attachments or entering credentials until the sender is independently verified."
    };
  }


  // MEDIUM
  if (score >= 34) {

    return {

      verdict:
        "Suspicious",

      color:
        "#F29900",

      description:
        "Some suspicious indicators were detected.",

      actionTitle:
        "Verify before taking action",

      actionText:
        "Check the sender and link destinations before replying, clicking or sharing information."
    };
  }


  // LOW
  return {

    verdict:
      "Low Risk",

    color:
      "#188038",

    description:
      "No strong malicious indicators were detected.",

    actionTitle:
      "No immediate action needed",

    actionText:
      "Still verify unexpected requests before sharing sensitive information."
  };
}


// ============================================================================
// 5. SCORE DOTS
// ============================================================================

function buildScoreDots(score) {

  const total = 10;

  const filled =
    Math.round(
      score / 10
    );


  let dots = "";


  for (
    let i = 0;
    i < total;
    i++
  ) {

    dots +=
      i < filled
        ? "● "
        : "○ ";
  }


  return (
    "<b>" +
    dots.trim() +
    "</b>"
  );
}


// ============================================================================
// 6. SIGNAL NORMALIZATION
// ============================================================================

function normalizeSignal(signal) {

  if (
    typeof signal === "string"
  ) {

    return {
      code: "",
      reason: signal
    };
  }


  return {

    code:
      signal.code || "",

    reason:
      signal.reason ||
      "Suspicious indicator detected"
  };
}


// ============================================================================
// 7. REMOVE DUPLICATES
// ============================================================================

function removeDuplicateSignals(
  signals
) {

  const seen = {};
  const uniqueSignals = [];


  signals.forEach(
    function(signal) {

      const normalized =
        normalizeSignal(signal);


      const key =
        normalized.code ||
        normalized.reason;


      if (!seen[key]) {

        seen[key] =
          true;

        uniqueSignals.push(
          signal
        );
      }
    }
  );


  return uniqueSignals;
}


// ============================================================================
// 8. FINDING TITLES
// ============================================================================

function getFindingTitle(code) {

  const titles = {

    suspicious_sender_domain:
      "Suspicious Sender",

    link_domain_mismatch:
      "Link Destination Mismatch",

    spf_fail:
      "SPF Authentication Failed",

    dkim_fail:
      "DKIM Authentication Failed",

    dmarc_fail:
      "DMARC Authentication Failed",

    urgent_language:
      "Urgency or Pressure Detected",

    shortened_url:
      "Shortened Link Detected",

    suspicious_ip_link:
      "Suspicious IP Link",

    brand_impersonation:
      "Possible Brand Impersonation",

    reply_to_mismatch:
      "Reply-To Mismatch"

  };


  return (
    titles[code] ||
    "Security Indicator"
  );
}


// ============================================================================
// 9. FINDING EMOJIS
// ============================================================================

function getFindingEmoji(code) {

  const emojis = {

    suspicious_sender_domain:
      "👤",

    link_domain_mismatch:
      "🔗",

    spf_fail:
      "🛡️",

    dkim_fail:
      "🛡️",

    dmarc_fail:
      "🛡️",

    urgent_language:
      "⏰",

    shortened_url:
      "🔗",

    suspicious_ip_link:
      "🌐",

    brand_impersonation:
      "⚠️",

    reply_to_mismatch:
      "📨"

  };


  return (
    emojis[code] ||
    "⚠️"
  );
}


// ============================================================================
// 10. SENDER
// ============================================================================

function parseSender(rawFrom) {

  const match =
    rawFrom.match(
      /^(.*)<(.+)>$/
    );


  if (match) {

    return {

      name:
        match[1]
          .trim()
          .replace(
            /^["']|["']$/g,
            ""
          ),

      email:
        match[2]
          .trim()
    };
  }


  return {

    name: "",

    email:
      rawFrom.trim()
  };
}


// ============================================================================
// 11. LINKS
// ============================================================================

function extractLinksFromHtml(
  htmlBody
) {

  const links = [];


  const regex =
    /<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;


  let match;


  while (
    (
      match =
        regex.exec(
          htmlBody
        )
    ) !== null
  ) {

    const actualUrl =
      decodeHtmlEntities(
        match[1]
      ).trim();


    const displayedText =
      stripHtml(
        match[2]
      ).trim();


    if (
      actualUrl.startsWith(
        "http://"
      ) ||
      actualUrl.startsWith(
        "https://"
      )
    ) {

      links.push({

        text:
          displayedText,

        url:
          actualUrl
      });
    }
  }


  return links;
}


function stripHtml(text) {

  return decodeHtmlEntities(

    text.replace(
      /<[^>]*>/g,
      ""
    )
  );
}


function decodeHtmlEntities(text) {

  return String(
    text || ""
  )

    .replace(
      /&amp;/g,
      "&"
    )

    .replace(
      /&quot;/g,
      "\""
    )

    .replace(
      /&#39;/g,
      "'"
    )

    .replace(
      /&lt;/g,
      "<"
    )

    .replace(
      /&gt;/g,
      ">"
    );
}


// ============================================================================
// 12. AUTHENTICATION
// Used by backend only - not displayed
// ============================================================================

function getAuthenticationResults(
  messageId
) {

  try {

    const apiMessage =
      Gmail.Users.Messages.get(
        "me",
        messageId,
        {
          format:
            "metadata",

          metadataHeaders: [
            "Authentication-Results"
          ]
        }
      );


    const headers =
      apiMessage.payload &&
      apiMessage.payload.headers

        ? apiMessage.payload.headers

        : [];


    let authenticationHeader =
      null;


    headers.forEach(
      function(header) {

        if (
          header.name &&
          header.name
            .toLowerCase() ===
            "authentication-results"
        ) {

          authenticationHeader =
            header.value;
        }
      }
    );


    if (
      !authenticationHeader
    ) {

      return {
        spf: null,
        dkim: null,
        dmarc: null
      };
    }


    return {

      spf:
        extractAuthValue(
          authenticationHeader,
          "spf"
        ),

      dkim:
        extractAuthValue(
          authenticationHeader,
          "dkim"
        ),

      dmarc:
        extractAuthValue(
          authenticationHeader,
          "dmarc"
        )
    };


  } catch (error) {

    console.log(
      "Authentication extraction error: " +
      error
    );


    return {
      spf: null,
      dkim: null,
      dmarc: null
    };
  }
}


function extractAuthValue(
  headerValue,
  type
) {

  const regex =
    new RegExp(
      type +
      "\\s*=\\s*([a-zA-Z0-9_-]+)",
      "i"
    );


  const match =
    headerValue.match(
      regex
    );


  return (
    match
      ? match[1]
          .toLowerCase()
      : null
  );
}


// ============================================================================
// 13. DELETE EMAIL
// ============================================================================

function handleDeleteEmail(e) {

  try {

    const messageId =
      getActionMessageId(e);


    if (!messageId) {

      throw new Error(
        "Missing messageId"
      );
    }


    Gmail.Users.Messages.trash(
      "me",
      messageId
    );


    return CardService
      .newActionResponseBuilder()

      .setNotification(
        CardService
          .newNotification()

          .setText(
            "Email moved to Trash"
          )
      )

      .build();


  } catch (error) {

    console.log(
      "Delete error: " +
      error
    );


    return CardService
      .newActionResponseBuilder()

      .setNotification(
        CardService
          .newNotification()

          .setText(
            "Could not move the email to Trash"
          )
      )

      .build();
  }
}


// ============================================================================
// 14. REPORT PHISHING
// MVP feedback action
// ============================================================================

function handleReportPhishing(e) {

  try {

    const messageId =
      getActionMessageId(e);


    if (!messageId) {

      throw new Error(
        "Missing messageId"
      );
    }


    // ------------------------------------------------------------------------
    // MVP:
    // Store / send this event to your backend later.
    // It currently records the user's feedback in Apps Script logs.
    // ------------------------------------------------------------------------

    console.log(
      JSON.stringify({
        event:
          "user_reported_phishing",

        messageId:
          messageId,

        timestamp:
          new Date().toISOString()
      })
    );


    return CardService
      .newActionResponseBuilder()

      .setNotification(
        CardService
          .newNotification()

          .setText(
            "Thanks — your phishing report was recorded"
          )
      )

      .build();


  } catch (error) {

    console.log(
      "Report phishing error: " +
      error
    );


    return CardService
      .newActionResponseBuilder()

      .setNotification(
        CardService
          .newNotification()

          .setText(
            "Could not report this email"
          )
      )

      .build();
  }
}


// ============================================================================
// 15. GET MESSAGE ID FROM ACTION
// ============================================================================

function getActionMessageId(e) {

  if (
    e &&
    e.commonEventObject &&
    e.commonEventObject.parameters &&
    e.commonEventObject.parameters.messageId
  ) {

    return e.commonEventObject
      .parameters
      .messageId;
  }


  if (
    e &&
    e.parameters &&
    e.parameters.messageId
  ) {

    return e.parameters.messageId;
  }


  return null;
}


// ============================================================================
// 16. ERROR CARD
// ============================================================================

function buildErrorCard(
  title,
  message
) {

  return CardService
    .newCardBuilder()

    .setHeader(
      CardService
        .newCardHeader()

        .setTitle(
          title
        )

        .setSubtitle(
          "Email Security Shield"
        )
    )

    .addSection(
      CardService
        .newCardSection()

        .addWidget(
          CardService
            .newTextParagraph()

            .setText(
              "⚠️ <b>" +
              escapeHtml(
                message
              ) +
              "</b>"
            )
        )
    )

    .build();
}


// ============================================================================
// 17. HTML SAFETY
// ============================================================================

function escapeHtml(value) {

  return String(
    value || ""
  )

    .replace(
      /&/g,
      "&amp;"
    )

    .replace(
      /</g,
      "&lt;"
    )

    .replace(
      />/g,
      "&gt;"
    )

    .replace(
      /"/g,
      "&quot;"
    )

    .replace(
      /'/g,
      "&#39;"
    );
}
