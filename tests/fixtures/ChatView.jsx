// Deliberately vulnerable fixture: model output rendered as raw HTML.
export const Chat = ({ reply }) => <div dangerouslySetInnerHTML={{ __html: reply.content }} />;  // ai.llm-output-html-sink
