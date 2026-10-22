import 'package:cipherbird_example/play/media/picked_media.dart';
import 'package:file_picker/file_picker.dart';

/// Opens the system file picker and returns the chosen file, or null when
/// the developer cancelled.
Future<PickedMedia?> pickMedia() async {
  final files = await FilePicker.pickFiles();
  if (files.isEmpty) {
    return null;
  }
  final file = files.first;
  return PickedMedia(file.name, await file.readAsBytes());
}
